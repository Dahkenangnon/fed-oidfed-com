import crypto from "node:crypto";
import type { AuthorityServer } from "@oidfed/authority";
import {
	type EntityId,
	type HttpClient,
	InMemoryJtiStore,
	type JWK,
	type TrustAnchorSet,
	decodeEntityStatement,
} from "@oidfed/core";
import { processAutomaticRegistration } from "@oidfed/oidc";
import cors from "cors";
import express, { type Express, type RequestHandler } from "express";
import Provider from "oidc-provider";

export interface OpExpressAppConfig {
	authority: AuthorityServer;
	entityId: string;
	trustAnchors: TrustAnchorSet;
	/**
	 * OP's private signing key. Reused for OIDC ID-token signing — single-key model is fine
	 * for the demo. Production deployments SHOULD split federation + OIDC signing keys.
	 */
	signingKey: JWK;
	/**
	 * Public form of the signing key, advertised in `jwks`.
	 */
	publicSigningKey: JWK;
	/**
	 * Outbound HTTP client for the OP's federation lookups (resolving the RP's
	 * trust chain during `processAutomaticRegistration`). Defaults to the global
	 * `fetch`. Override for hermetic integration tests, request-throttling
	 * proxies, or fetch-policy enforcement (allowed-hosts, CIDR blocks, etc.).
	 */
	httpClient?: HttpClient;
}

/**
 * Express factory for a leaf OP — mounts the federation endpoint surface alongside a
 * `node-oidc-provider` instance, plus custom interactions (login + consent) and the
 * federation-to-provider client adapter that makes federation-registered clients
 * addressable to the provider at /auth and /token.
 *
 * Stays on Express because `node-oidc-provider` is Node-only (depends on Node streams
 * and koa-compose). The federation endpoint subset (federation_fetch, federation_list,
 * federation_resolve, federation_registration, federation_trust_mark*) is mounted via
 * the upstream `authority.handler()`.
 *
 * Two OIDC integration points:
 *
 *   • `/auth` is intercepted to detect an inbound Request Object (`?request=`) and
 *     run it through `processAutomaticRegistration` before forwarding to
 *     `node-oidc-provider`. On success, the resolved RP metadata is registered with
 *     the provider's client adapter so the rest of the flow can address the client.
 *     On failure, the canonical OIDC error JSON is returned to the user-agent (never
 *     redirected to the RP — federation trust failures must not leak to redirect_uri).
 *
 *   • `/federation_registration` is forwarded to `authority.handler()`. The response
 *     is intercepted to capture the OP-assigned `client_id` (and optional
 *     `client_secret`) and register the client with the provider's adapter, so the
 *     subsequent OIDC flow can authenticate the RP.
 *
 * The OIDC issuer claim is set to the public entityId, which MUST match the subdomain
 * that dispatches to this app.
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/participants/openid-provider-app.ts
 */
export function createOpExpressApp(config: OpExpressAppConfig): Express {
	const {
		authority,
		entityId,
		trustAnchors,
		signingKey,
		publicSigningKey,
		httpClient = fetch,
	} = config;

	// In-memory storage for the federation-registered clients (and the OIDC state node-oidc-provider
	// needs for sessions, grants, codes, tokens). Lives for the OP process lifetime.
	const clientStore = new Map<string, StoredClient>();
	const Adapter = createInMemoryAdapter(clientStore);

	const oidc = new Provider(entityId, {
		adapter: Adapter,
		jwks: { keys: [signingKey] },
		claims: {
			openid: ["sub"],
			profile: ["name", "preferred_username"],
			email: ["email", "email_verified"],
		},
		scopes: ["openid", "profile", "email"],
		responseTypes: ["code"],
		clientAuthMethods: ["private_key_jwt", "none"],
		// Cookie signing key derived from the OP's signing key so in-flight sessions,
		// authorization codes, grants, and CSRF cookies survive a process restart.
		// Same pattern as demo-rp.ts:deriveCookieSecret.
		cookies: { keys: [deriveCookieSecret(signingKey).toString("base64")] },
		// Explicit TTLs across every artifact type — silences node-oidc-provider's
		// default-TTL NOTICE warnings and pins values across upstream versions.
		ttl: {
			AuthorizationCode: 60,
			IdToken: 3600,
			AccessToken: 3600,
			Interaction: 600,
			Session: 3600,
			Grant: 600,
		},
		findAccount: async (_ctx, sub) => ({
			accountId: sub,
			claims: async (_use, scope) => {
				const c: { sub: string; [k: string]: unknown } = { sub };
				if (scope.includes("profile")) {
					c.name = "Alice (demo)";
					c.preferred_username = "alice";
				}
				if (scope.includes("email")) {
					c.email = "alice@example.com";
					c.email_verified = true;
				}
				return c;
			},
		}),
		interactions: {
			url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
		},
		features: {
			registration: { enabled: false }, // federation handles its own
			requestObjects: { enabled: true }, // Request Objects are the automatic-registration carrier
			devInteractions: { enabled: false }, // we serve our own UI below
			rpMetadataChoices: { enabled: true }, // OIDC RP Metadata Choices — narrows array-valued client metadata at request time
			rpInitiatedLogout: { enabled: true },
		},
		// Produce a consistent JSON error envelope across all error responses.
		renderError: async (ctx, out, _error) => {
			ctx.type = "application/json";
			ctx.body = {
				error: out.error,
				error_description: out.error_description,
				entity_id: entityId,
				entity_type: "openid-provider",
			};
		},
	});
	oidc.proxy = true;

	oidc.on("server_error", (_ctx, err: Error) => {
		// Sanitized server-side logging — error never leaks to the response body.
		console.error(`[op:${entityId}] server_error: ${err.message}`);
	});

	const jtiStore = new InMemoryJtiStore();
	const federationHandler = authority.handler();
	const app = express();

	app.use(
		cors({
			origin: true,
			methods: ["GET", "POST", "OPTIONS"],
			allowedHeaders: ["Content-Type", "Accept"],
			maxAge: 86400,
		}),
	);
	app.use(express.raw({ type: "application/entity-statement+jwt", limit: "64kb" }));
	app.use(express.urlencoded({ extended: false, limit: "64kb" }));

	// ── Federation surface ───────────────────────────────────────────────────
	app.all("/.well-known/openid-federation", async (req, res) => {
		const url = new URL(req.originalUrl, entityId);
		const request = new Request(url.toString(), { method: "GET" });
		const response = await federationHandler(request);
		res.status(response.status);
		for (const [key, value] of response.headers) res.setHeader(key, value);
		res.send(await response.text());
	});

	// All federation paths except /federation_registration get the simple forwarding.
	// /federation_registration is intercepted to capture the OP-issued registration response
	// and register the resulting client with the provider's adapter.
	const SIMPLE_FEDERATION_PATHS = [
		"/federation_fetch",
		"/federation_list",
		"/federation_resolve",
		"/federation_trust_mark",
		"/federation_trust_mark_status",
		"/federation_trust_mark_list",
	];
	for (const path of SIMPLE_FEDERATION_PATHS) {
		app.all(path, async (req, res) => {
			const request = await toFetchRequest(req, entityId);
			const response = await federationHandler(request);
			res.status(response.status);
			for (const [key, value] of response.headers) res.setHeader(key, value);
			res.send(await response.text());
		});
	}

	app.all("/federation_registration", async (req, res) => {
		const request = await toFetchRequest(req, entityId);
		const response = await federationHandler(request);

		// On a 200, decode the explicit-registration response and register the resulting
		// client. The response shape is fixed: typ=explicit-registration-response+jwt,
		// metadata.openid_relying_party contains the resolved client metadata including
		// the OP-assigned client_id (and optional client_secret).
		if (response.status === 200) {
			try {
				const respJwt = await response.clone().text();
				const decoded = decodeEntityStatement(respJwt);
				if (!decoded.ok) {
					console.error(
						`[op:${entityId}] failed to decode explicit-registration response: ${decoded.error.description}`,
					);
				} else {
					const payload = decoded.value.payload as Record<string, unknown>;
					const metaContainer = payload.metadata as
						| Record<string, Record<string, unknown>>
						| undefined;
					const rpMeta = metaContainer?.openid_relying_party;
					if (!rpMeta || typeof rpMeta.client_id !== "string") {
						console.error(
							`[op:${entityId}] explicit-registration response missing openid_relying_party.client_id — client will not be registered with the OIDC adapter`,
						);
					} else {
						const authMethod =
							(rpMeta.token_endpoint_auth_method as string) || "client_secret_basic";
						registerClient(clientStore, {
							client_id: rpMeta.client_id,
							client_secret:
								typeof rpMeta.client_secret === "string" ? rpMeta.client_secret : undefined,
							redirect_uris: (rpMeta.redirect_uris as string[]) || [],
							response_types: (rpMeta.response_types as string[]) || ["code"],
							grant_types: (rpMeta.grant_types as string[]) || ["authorization_code"],
							token_endpoint_auth_method: authMethod,
							token_endpoint_auth_signing_alg:
								(rpMeta.token_endpoint_auth_signing_alg as string | undefined) ??
								(authMethod === "private_key_jwt" ? DEFAULT_SIGNING_ALG : undefined),
							id_token_signed_response_alg:
								(rpMeta.id_token_signed_response_alg as string | undefined) ?? DEFAULT_SIGNING_ALG,
							request_object_signing_alg:
								(rpMeta.request_object_signing_alg as string | undefined) ?? DEFAULT_SIGNING_ALG,
							jwks: rpMeta.jwks as { keys: JWK[] } | undefined,
							application_type: "web",
						});
					}
				}
			} catch (err) {
				console.error(
					`[op:${entityId}] error registering client from explicit-registration response: ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		}

		res.status(response.status);
		for (const [key, value] of response.headers) res.setHeader(key, value);
		res.send(await response.text());
	});

	// ── Custom interactions UI ───────────────────────────────────────────────
	app.get("/interaction/:uid", async (req, res) => {
		try {
			const { prompt, params, uid } = await oidc.interactionDetails(req, res);
			res.type("html").send(renderInteractionPage(prompt.name, params, uid));
		} catch {
			res
				.status(400)
				.type("application/json")
				.send(
					JSON.stringify({
						error: "invalid_interaction",
						error_description: "Interaction not found or expired.",
						entity_id: entityId,
						entity_type: "openid-provider",
					}),
				);
		}
	});

	app.post("/interaction/:uid/login", async (req, res) => {
		try {
			await oidc.interactionFinished(
				req,
				res,
				{
					login: {
						accountId: "alice@example.com",
						acr: "0",
						amr: ["fixed"],
						remember: false,
						ts: Math.floor(Date.now() / 1000),
					},
				},
				{ mergeWithLastSubmission: false },
			);
		} catch {
			res
				.status(400)
				.type("application/json")
				.send(
					JSON.stringify({
						error: "invalid_interaction",
						error_description: "Could not complete login.",
						entity_id: entityId,
						entity_type: "openid-provider",
					}),
				);
		}
	});

	app.post("/interaction/:uid/confirm", async (req, res) => {
		try {
			const details = await oidc.interactionDetails(req, res);
			const { params, session } = details;
			const clientIdParam = String(params.client_id ?? "");
			const accountId = String(session?.accountId ?? "");
			const grant = new oidc.Grant({ clientId: clientIdParam, accountId });
			grant.addOIDCScope(String(params.scope ?? "openid"));
			const grantId = await grant.save();
			await oidc.interactionFinished(
				req,
				res,
				{ consent: { grantId } },
				{ mergeWithLastSubmission: true },
			);
		} catch {
			res
				.status(400)
				.type("application/json")
				.send(
					JSON.stringify({
						error: "invalid_interaction",
						error_description: "Could not complete consent.",
						entity_id: entityId,
						entity_type: "openid-provider",
					}),
				);
		}
	});

	app.post("/interaction/:uid/abort", async (req, res) => {
		try {
			await oidc.interactionFinished(req, res, {
				error: "access_denied",
				error_description: "End-User aborted interaction.",
			});
		} catch {
			res.redirect("/");
		}
	});

	// ── /auth interception for automatic federation registration ─────────────
	app.get("/auth", async (req, res, next) => {
		const requestJwt = req.query.request as string | undefined;
		if (requestJwt) {
			const result = await processAutomaticRegistration(requestJwt, trustAnchors, {
				opEntityId: entityId as EntityId,
				jtiStore,
				httpClient,
			});
			if (!result.ok) {
				// Trust-failure errors are returned to the user-agent, NOT to redirect_uri.
				res
					.status(400)
					.type("application/json")
					.send(
						JSON.stringify({
							error: result.error.code,
							error_description: result.error.description,
							entity_id: entityId,
							entity_type: "openid-provider",
						}),
					);
				return;
			}

			const rpMeta = result.value.resolvedRpMetadata as Record<string, unknown>;
			// jwks fallback: prefer openid_relying_party.jwks, then fall back to the
			// federation EC's top-level jwks (the leaf statement in the resolved chain).
			const leafStmt = result.value.trustChain.statements[0];
			const fedJwks = leafStmt?.payload.jwks as { keys: JWK[] } | undefined;
			const rpJwks = (rpMeta.jwks as { keys: JWK[] } | undefined) ?? fedJwks;
			registerClient(clientStore, {
				client_id: result.value.rpEntityId,
				redirect_uris: (rpMeta.redirect_uris as string[]) || [],
				response_types: (rpMeta.response_types as string[]) || ["code"],
				grant_types: (rpMeta.grant_types as string[]) || ["authorization_code"],
				// Automatic registration uses asymmetric crypto only; never a client_secret.
				token_endpoint_auth_method: "private_key_jwt",
				token_endpoint_auth_signing_alg:
					(rpMeta.token_endpoint_auth_signing_alg as string | undefined) ?? DEFAULT_SIGNING_ALG,
				id_token_signed_response_alg:
					(rpMeta.id_token_signed_response_alg as string | undefined) ?? DEFAULT_SIGNING_ALG,
				request_object_signing_alg:
					(rpMeta.request_object_signing_alg as string | undefined) ?? DEFAULT_SIGNING_ALG,
				jwks: rpJwks,
				application_type: "web",
				// NEVER set client_secret on automatic registration.
			});
		}
		const handler = oidc.callback() as RequestHandler;
		return handler(req, res, next);
	});

	// ── Unified JSON envelope for the root path ──────────────────────────────
	app.get("/", (_req, res) => {
		res
			.status(404)
			.type("application/json")
			.send(
				JSON.stringify({
					error: "not_found",
					error_description:
						"This is an OpenID Provider entity. Use /auth, /token, /jwks, /.well-known/openid-configuration, or /.well-known/openid-federation.",
					entity_id: entityId,
					entity_type: "openid-provider",
				}),
			);
	});

	// Everything else (OIDC discovery, token, userinfo, jwks, end-session, …) goes to the provider.
	app.use("/", oidc.callback() as RequestHandler);

	// Silence unused-variable linter for publicSigningKey — kept on the config interface for
	// symmetry and for a future enhancement that publishes a separate OIDC JWKS endpoint.
	void publicSigningKey;

	return app;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory adapter for node-oidc-provider
// ─────────────────────────────────────────────────────────────────────────────

interface StoredClient {
	client_id: string;
	client_secret?: string | undefined;
	redirect_uris: string[];
	response_types: string[];
	grant_types: string[];
	token_endpoint_auth_method: string;
	token_endpoint_auth_signing_alg?: string | undefined;
	id_token_signed_response_alg?: string | undefined;
	request_object_signing_alg?: string | undefined;
	jwks?: { keys: JWK[] } | undefined;
	jwks_uri?: string | undefined;
	application_type: "web" | "native";
}

// OIDC ID-token / token-endpoint algorithm — single-key model uses ES256 (matches
// the topology's `id_token_signing_alg_values_supported`). Stored clients inherit
// this default when their published metadata doesn't pin a value explicitly.
const DEFAULT_SIGNING_ALG = "ES256";

/** Idempotent client registration — accepts repeated calls (e.g. a federated client re-registering). */
function registerClient(store: Map<string, StoredClient>, client: StoredClient): void {
	const sanitized: StoredClient = {
		...client,
		redirect_uris: client.redirect_uris.filter(
			(u) => typeof u === "string" && u.startsWith("https://"),
		),
	};
	store.set(client.client_id, sanitized);
}

/**
 * Returns an Adapter constructor for `node-oidc-provider`. The `Client` model consults
 * the federation-populated `clientStore`; every other model gets a per-model in-memory
 * map with TTL-based expiry, since node-oidc-provider needs persistent state for
 * Sessions, Grants, AuthorizationCodes, AccessTokens, IdTokens, and so on.
 *
 * Demo-grade — fine for a single-process OP that resets on restart. A production
 * deployment would swap this for a Redis-backed adapter (the shape is identical;
 * see node-oidc-provider's example adapters).
 */
function createInMemoryAdapter(clientStore: Map<string, StoredClient>) {
	interface Slot {
		payload: Record<string, unknown>;
		expiresAt: number;
	}
	const stores = new Map<string, Map<string, Slot>>();
	const byUid = new Map<string, Map<string, string>>();
	const byUserCode = new Map<string, Map<string, string>>();
	const grantGroups = new Map<string, Set<string>>();

	function bucket(name: string): Map<string, Slot> {
		let s = stores.get(name);
		if (!s) {
			s = new Map();
			stores.set(name, s);
		}
		return s;
	}

	return class Adapter {
		readonly name: string;
		constructor(name: string) {
			this.name = name;
		}

		async upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void> {
			if (this.name === "Client") return; // Clients are federation-managed.
			const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : Number.MAX_SAFE_INTEGER;
			bucket(this.name).set(id, { payload, expiresAt });
			const uid = payload.uid;
			if (typeof uid === "string") {
				let m = byUid.get(this.name);
				if (!m) {
					m = new Map();
					byUid.set(this.name, m);
				}
				m.set(uid, id);
			}
			const userCode = payload.userCode;
			if (typeof userCode === "string") {
				let m = byUserCode.get(this.name);
				if (!m) {
					m = new Map();
					byUserCode.set(this.name, m);
				}
				m.set(userCode, id);
			}
			const grantId = payload.grantId;
			if (typeof grantId === "string") {
				let g = grantGroups.get(grantId);
				if (!g) {
					g = new Set();
					grantGroups.set(grantId, g);
				}
				g.add(`${this.name}:${id}`);
			}
		}

		async find(id: string): Promise<Record<string, unknown> | undefined> {
			if (this.name === "Client") {
				const c = clientStore.get(id);
				return c ? (c as unknown as Record<string, unknown>) : undefined;
			}
			const slot = bucket(this.name).get(id);
			if (!slot) return undefined;
			if (slot.expiresAt && slot.expiresAt < Date.now()) {
				bucket(this.name).delete(id);
				return undefined;
			}
			return slot.payload;
		}

		async findByUid(uid: string): Promise<Record<string, unknown> | undefined> {
			const id = byUid.get(this.name)?.get(uid);
			return id ? this.find(id) : undefined;
		}

		async findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined> {
			const id = byUserCode.get(this.name)?.get(userCode);
			return id ? this.find(id) : undefined;
		}

		async consume(id: string): Promise<void> {
			const slot = bucket(this.name).get(id);
			if (slot) {
				slot.payload.consumed = Math.floor(Date.now() / 1000);
			}
		}

		async destroy(id: string): Promise<void> {
			bucket(this.name).delete(id);
		}

		async revokeByGrantId(grantId: string): Promise<void> {
			const g = grantGroups.get(grantId);
			if (!g) return;
			for (const key of g) {
				const sep = key.indexOf(":");
				const name = key.slice(0, sep);
				const id = key.slice(sep + 1);
				stores.get(name)?.delete(id);
			}
			grantGroups.delete(grantId);
		}
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derive a deterministic 32-byte cookie-signing secret from the OP's JWK private fields.
 * The resulting secret is stable across process restarts (so existing cookies remain
 * verifiable) but rotates whenever the OP's signing key rotates.
 */
function deriveCookieSecret(signingKey: JWK): Buffer {
	const seed = JSON.stringify({
		k: signingKey.kid ?? "",
		d: signingKey.d ?? "",
		x: signingKey.x ?? "",
		y: signingKey.y ?? "",
	});
	return crypto.createHash("sha256").update(seed).digest();
}

async function toFetchRequest(req: express.Request, entityIdBase: string): Promise<Request> {
	const url = new URL(req.originalUrl, entityIdBase);
	const hasBody = req.method !== "GET" && req.method !== "HEAD";
	let body: BodyInit | undefined;
	if (hasBody) {
		if (Buffer.isBuffer(req.body)) {
			body = new Uint8Array(req.body);
		} else if (typeof req.body === "object" && req.body !== null) {
			body = new URLSearchParams(req.body as Record<string, string>).toString();
		}
	}
	return new Request(url.toString(), {
		method: req.method,
		headers: req.headers as Record<string, string>,
		...(body !== undefined ? { body } : {}),
	});
}

function htmlEscape(s: unknown): string {
	return String(s).replace(/[&<>"']/g, (c) => {
		switch (c) {
			case "&":
				return "&amp;";
			case "<":
				return "&lt;";
			case ">":
				return "&gt;";
			case '"':
				return "&quot;";
			case "'":
				return "&#39;";
			default:
				return c;
		}
	});
}

function renderInteractionPage(
	promptName: string,
	params: Record<string, unknown>,
	uid: string,
): string {
	if (promptName === "login") return renderLoginPage(params, uid);
	if (promptName === "consent") return renderConsentPage(params, uid);
	return `<!doctype html><html lang=en><head><meta charset=utf-8><title>Interaction</title></head>
<body><h1>Unsupported interaction</h1><p>Prompt: <code>${htmlEscape(promptName)}</code></p></body></html>`;
}

function renderLoginPage(params: Record<string, unknown>, uid: string): string {
	return `<!doctype html><html lang=en><head><meta charset=utf-8><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
<p>Client: <code>${htmlEscape(params.client_id)}</code></p>
<p>Scope: <code>${htmlEscape(params.scope)}</code></p>
<form method=post action=/interaction/${htmlEscape(uid)}/login>
<button type=submit>Continue as alice@example.com</button>
</form>
<form method=post action=/interaction/${htmlEscape(uid)}/abort>
<button type=submit>Cancel</button>
</form>
</body></html>`;
}

function renderConsentPage(params: Record<string, unknown>, uid: string): string {
	const scopes = String(params.scope ?? "")
		.split(" ")
		.filter(Boolean);
	const items = scopes.map((s) => `<li><code>${htmlEscape(s)}</code></li>`).join("");
	return `<!doctype html><html lang=en><head><meta charset=utf-8><title>Authorize</title></head>
<body>
<h1>Authorize ${htmlEscape(params.client_id)}</h1>
<p>This application is requesting access to:</p>
<ul>${items}</ul>
<form method=post action=/interaction/${htmlEscape(uid)}/confirm>
<button type=submit>Allow</button>
</form>
<form method=post action=/interaction/${htmlEscape(uid)}/abort>
<button type=submit>Deny</button>
</form>
</body></html>`;
}
