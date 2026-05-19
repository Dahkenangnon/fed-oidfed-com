/**
 * Demo RP — Hono app that drives a full OpenID Federation 1.0 → OIDC flow end-to-end
 * for a visitor in a browser. Replaces the bare leaf factory for the small set of RPs
 * that participate in the visible demo (currently `rp1.single` and `rp2.single`).
 *
 * Routes:
 *   GET  /.well-known/openid-federation  — delegate to the leaf handler (same as leaf.ts).
 *   GET  /                               — landing page with a "Sign in via OP" link.
 *   GET  /start-login                    — initiates the flow: discoverEntity → register
 *                                          (automaticRegistration or explicitRegistration),
 *                                          set signed state+nonce cookies, redirect to the
 *                                          OP authorization URL.
 *   GET  /callback                       — receives the auth code, validates state,
 *                                          exchanges via private_key_jwt at the OP token
 *                                          endpoint, renders the decoded ID token + trust
 *                                          chain.
 *
 * Defined paths above; everything else returns the unified JSON 404 envelope shared with
 * the other participants.
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/scenarios/oidc-login-flow.test.ts
 */

import crypto from "node:crypto";
import type { EntityId, HttpClient, JWK, TrustAnchorSet } from "@oidfed/core";
import { entityId as toEntityId } from "@oidfed/core";
import { type LeafEntity, discoverEntity } from "@oidfed/leaf";
import {
	type RequestDelivery,
	automaticRegistration,
	createClientAssertion,
	explicitRegistration,
} from "@oidfed/oidc";
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { cors } from "hono/cors";
import * as jose from "jose";

const STATE_COOKIE = "fed_oidfed_state";
const NONCE_COOKIE = "fed_oidfed_nonce";
const CLIENT_CACHE_COOKIE = "fed_oidfed_cid";
const COOKIE_MAX_AGE = 300; // 5 minutes
const FLOW_CACHE_TTL_MS = 5 * 60 * 1000;

interface DemoRpConfig {
	leaf: LeafEntity;
	entityId: string;
	opEntityId: string;
	signingKey: JWK;
	publicSigningKey: JWK;
	trustAnchors: TrustAnchorSet;
	metadata: Record<string, Record<string, unknown>>;
	registrationMode: "automatic" | "explicit";
	/**
	 * The RP's immediate superiors, as declared by topology. Used verbatim as the
	 * `authority_hints` claim in the explicit-registration Entity Configuration
	 * (the RP's own EC, not the OP's). Spec requires every hint to lead to at
	 * least one of the Trust Anchors in the chosen subset.
	 */
	authorityHints: ReadonlyArray<string>;
	/**
	 * How the signed Request Object reaches the OP authorization endpoint
	 * during automatic registration. Defaults to "form_post" — the safe
	 * choice for chain-bearing Request Objects. Ignored when
	 * registrationMode === "explicit".
	 */
	requestDelivery?: RequestDelivery;
	httpClient?: HttpClient;
}

interface FlowState {
	clientId: string;
	clientSecret?: string;
	nonce: string;
	expiresAt: number;
}

export function createDemoRpHonoApp(config: DemoRpConfig): Hono {
	const {
		leaf,
		entityId,
		opEntityId,
		signingKey,
		trustAnchors,
		metadata,
		registrationMode,
		authorityHints,
		requestDelivery = "form_post",
		httpClient = fetch,
	} = config;
	const rpAuthorityHints = authorityHints.map((h) => toEntityId(h));

	const app = new Hono();
	const leafHandler = leaf.handler();
	const cookieSecret = deriveCookieSecret(signingKey);
	// Per-flow cache keyed by state — survives the redirect to the OP and back.
	// Cleared on use or TTL expiry. Demo-grade single-process storage.
	const flowCache = new Map<string, FlowState>();
	// Per-process cache of Request Object JWTs hosted under /request-object/:id
	// for the by-reference delivery mode. Entries TTL out after 60 seconds.
	const requestObjectStore = new Map<string, { jwt: string; expiresAt: number }>();
	const REQUEST_OBJECT_TTL_MS = 60_000;

	app.use(
		"*",
		cors({
			origin: "*",
			allowMethods: ["GET", "POST", "OPTIONS"],
			allowHeaders: ["Content-Type", "Accept"],
			maxAge: 86400,
		}),
	);

	// ── Federation surface ───────────────────────────────────────────────────
	app.get("/.well-known/openid-federation", async () => {
		const request = new Request(`${entityId}/.well-known/openid-federation`, { method: "GET" });
		return leafHandler(request);
	});

	// ── Landing page ─────────────────────────────────────────────────────────
	app.get("/", (c) => {
		return c.html(
			renderLandingPage({
				entityId,
				opEntityId,
				registrationMode,
				requestDelivery,
			}),
		);
	});

	// ── Start login ──────────────────────────────────────────────────────────
	app.get("/start-login", async (c) => {
		try {
			const state = crypto.randomUUID();
			const nonce = crypto.randomUUID();
			const redirectUri = `${entityId}/callback`;

			const discovery = await discoverEntity(toEntityId(opEntityId), trustAnchors, { httpClient });

			const rpMeta = metadata.openid_relying_party as Record<string, unknown> | undefined;
			if (!rpMeta) {
				return jsonError(c, "missing_rp_metadata", "RP has no openid_relying_party metadata.");
			}

			// Discriminated result of the login dispatch: either a redirect URL,
			// or a form-post HTML page rendered locally.
			type Dispatch =
				| { kind: "redirect"; url: string }
				| { kind: "form_post"; action: string; fields: Record<string, string> };

			let dispatch: Dispatch;
			let cachedClientId: string;
			let cachedClientSecret: string | undefined;

			if (registrationMode === "automatic") {
				// For request_uri delivery, allocate a hosted slot up-front so the URL
				// can be passed into the lib. The signed JWT will be cached after sign.
				let hostedRequestUri: string | undefined;
				let hostedRequestId: string | undefined;
				if (requestDelivery === "request_uri") {
					hostedRequestId = crypto.randomUUID();
					hostedRequestUri = `${entityId}/request-object/${hostedRequestId}`;
				}

				const result = await automaticRegistration(
					discovery,
					{
						entityId: toEntityId(entityId),
						signingKeys: [signingKey as Record<string, unknown>],
						authorityHints: rpAuthorityHints,
						metadata: { openid_relying_party: rpMeta },
						requestDelivery,
						...(hostedRequestUri !== undefined ? { requestUri: hostedRequestUri } : {}),
					},
					{
						client_id: entityId,
						redirect_uri: redirectUri,
						response_type: "code",
						scope: "openid profile email",
						state,
						nonce,
					},
					trustAnchors,
					{ httpClient },
				);
				cachedClientId = entityId; // client_id equals the RP Entity Identifier for automatic registration

				switch (result.delivery) {
					case "query":
					case "par":
						dispatch = { kind: "redirect", url: result.authorizationUrl };
						break;
					case "request_uri":
						if (hostedRequestId !== undefined) {
							pruneRequestObjectStore(requestObjectStore);
							requestObjectStore.set(hostedRequestId, {
								jwt: result.requestObjectJwt,
								expiresAt: Date.now() + REQUEST_OBJECT_TTL_MS,
							});
						}
						dispatch = { kind: "redirect", url: result.authorizationUrl };
						break;
					case "form_post":
						dispatch = {
							kind: "form_post",
							action: result.authorizationEndpoint,
							fields: result.formParams,
						};
						break;
				}
			} else {
				const result = await explicitRegistration(
					discovery,
					{
						entityId: toEntityId(entityId),
						signingKeys: [signingKey as Record<string, unknown>],
						authorityHints: rpAuthorityHints,
						metadata: { openid_relying_party: rpMeta },
					},
					trustAnchors,
					{ httpClient },
				);
				cachedClientId = result.clientId;
				cachedClientSecret = result.clientSecret;
				const opMeta = discovery.resolvedMetadata.openid_provider as
					| Record<string, unknown>
					| undefined;
				const authEndpoint = opMeta?.authorization_endpoint;
				if (typeof authEndpoint !== "string") {
					return jsonError(c, "op_metadata_invalid", "OP has no authorization_endpoint.");
				}
				const url = new URL(authEndpoint);
				url.searchParams.set("client_id", cachedClientId);
				url.searchParams.set("redirect_uri", redirectUri);
				url.searchParams.set("response_type", "code");
				url.searchParams.set("scope", "openid profile email");
				url.searchParams.set("state", state);
				url.searchParams.set("nonce", nonce);
				dispatch = { kind: "redirect", url: url.toString() };
			}

			pruneFlowCache(flowCache);
			flowCache.set(state, {
				clientId: cachedClientId,
				...(cachedClientSecret !== undefined ? { clientSecret: cachedClientSecret } : {}),
				nonce,
				expiresAt: Date.now() + FLOW_CACHE_TTL_MS,
			});

			setCookie(c, STATE_COOKIE, signValue(state, cookieSecret), {
				httpOnly: true,
				sameSite: "Lax",
				path: "/",
				maxAge: COOKIE_MAX_AGE,
			});
			setCookie(c, NONCE_COOKIE, signValue(nonce, cookieSecret), {
				httpOnly: true,
				sameSite: "Lax",
				path: "/",
				maxAge: COOKIE_MAX_AGE,
			});
			setCookie(c, CLIENT_CACHE_COOKIE, signValue(cachedClientId, cookieSecret), {
				httpOnly: true,
				sameSite: "Lax",
				path: "/",
				maxAge: COOKIE_MAX_AGE,
			});

			if (dispatch.kind === "form_post") {
				return c.html(renderAutoSubmitForm(dispatch.action, dispatch.fields), 200);
			}
			return c.redirect(dispatch.url, 302);
		} catch (err) {
			return jsonError(
				c,
				"start_login_failed",
				err instanceof Error ? err.message : "Unknown error initiating login.",
				500,
			);
		}
	});

	// ── Callback: code exchange + ID-token render ────────────────────────────
	app.get("/callback", async (c) => {
		const code = c.req.query("code");
		const stateParam = c.req.query("state");
		const issParam = c.req.query("iss");
		const errorParam = c.req.query("error");

		if (errorParam) {
			return c.html(
				renderResultPage({
					ok: false,
					title: "Authorization error",
					body: `<p>The OP returned an error: <code>${htmlEscape(errorParam)}</code> — <code>${htmlEscape(c.req.query("error_description") ?? "")}</code></p>`,
				}),
				400,
			);
		}

		if (!code || !stateParam) {
			return jsonError(c, "invalid_callback", "Missing code or state.", 400);
		}

		const stateCookieRaw = getCookie(c, STATE_COOKIE);
		const stateCookie = stateCookieRaw ? unsignValue(stateCookieRaw, cookieSecret) : undefined;
		if (
			!stateCookie ||
			!crypto.timingSafeEqual(Buffer.from(stateCookie), Buffer.from(stateParam))
		) {
			return jsonError(c, "invalid_state", "State cookie mismatch.", 400);
		}

		const nonceCookieRaw = getCookie(c, NONCE_COOKIE);
		const expectedNonce = nonceCookieRaw ? unsignValue(nonceCookieRaw, cookieSecret) : undefined;
		if (!expectedNonce) {
			return jsonError(c, "invalid_nonce", "Nonce cookie missing.", 400);
		}

		const clientIdCookieRaw = getCookie(c, CLIENT_CACHE_COOKIE);
		const clientId = clientIdCookieRaw ? unsignValue(clientIdCookieRaw, cookieSecret) : undefined;
		if (!clientId) {
			return jsonError(c, "invalid_client", "Client cookie missing.", 400);
		}

		if (issParam && issParam !== opEntityId) {
			return jsonError(
				c,
				"invalid_issuer",
				`Authorization Server issuer (${issParam}) does not match configured OP (${opEntityId}).`,
				400,
			);
		}

		// Cached flow state (clientSecret for explicit, nonce reference).
		const flow = flowCache.get(stateParam);
		flowCache.delete(stateParam);

		// Discover the OP — needed for both the token endpoint and the jwks used to
		// verify the inbound ID token signature.
		let opDiscovery: Awaited<ReturnType<typeof discoverEntity>>;
		try {
			opDiscovery = await discoverEntity(toEntityId(opEntityId), trustAnchors, { httpClient });
		} catch (err) {
			return jsonError(
				c,
				"op_discovery_failed",
				err instanceof Error ? err.message : "Unknown error.",
				502,
			);
		}
		const opMeta = opDiscovery.resolvedMetadata.openid_provider as
			| Record<string, unknown>
			| undefined;
		const tokenEndpoint = opMeta?.token_endpoint;
		if (typeof tokenEndpoint !== "string") {
			return jsonError(c, "op_metadata_invalid", "OP has no token_endpoint.", 502);
		}
		// OP's signing jwks — prefer openid_provider.jwks (OIDC discovery shape), fall back to
		// the federation EC top-level jwks (the leaf statement in the OP's trust chain). In our
		// single-key model these resolve to the same JWK.
		const opOidcJwks = opMeta?.jwks as { keys: JWK[] } | undefined;
		const opFedJwks = opDiscovery.trustChain.statements[0]?.payload.jwks as
			| { keys: JWK[] }
			| undefined;
		const opJwks = opOidcJwks ?? opFedJwks;
		if (!opJwks || !Array.isArray(opJwks.keys) || opJwks.keys.length === 0) {
			return jsonError(c, "op_jwks_missing", "OP trust chain has no jwks for verification.", 502);
		}

		// Use the OP's issuer URL as the assertion audience. The token endpoint URL
		// is also accepted by node-oidc-provider, but the issuer form is more robust
		// against reverse-proxy URL rewriting (Host/Forwarded mismatches).
		const clientAssertion = await createClientAssertion(
			clientId as EntityId,
			opEntityId as EntityId,
			signingKey,
			{ expiresInSeconds: 60 },
		);

		const body = new URLSearchParams();
		body.set("grant_type", "authorization_code");
		body.set("code", code);
		body.set("redirect_uri", `${entityId}/callback`);
		body.set("client_id", clientId);
		body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		body.set("client_assertion", clientAssertion);
		if (flow?.clientSecret) {
			body.set("client_secret", flow.clientSecret);
		}

		const tokenResponse = await httpClient(tokenEndpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json",
			},
			body: body.toString(),
		});

		if (!tokenResponse.ok) {
			const text = await tokenResponse.text();
			return c.html(
				renderResultPage({
					ok: false,
					title: "Token exchange failed",
					body: `<p>The OP returned HTTP ${tokenResponse.status}.</p><pre>${htmlEscape(text)}</pre>`,
				}),
				400,
			);
		}

		const tokenJson = (await tokenResponse.json()) as Record<string, unknown>;
		const idToken = tokenJson.id_token;
		if (typeof idToken !== "string") {
			return c.html(
				renderResultPage({
					ok: false,
					title: "No ID token in response",
					body: `<pre>${htmlEscape(JSON.stringify(tokenJson, null, 2))}</pre>`,
				}),
				400,
			);
		}

		// Verify the ID token signature against the OP's jwks resolved through the
		// federation. This is mandatory before trusting any claim values.
		const verifyResult = await verifyOpSignedIdToken(idToken, opJwks, opEntityId, clientId);
		if (!verifyResult.ok) {
			return c.html(
				renderResultPage({
					ok: false,
					title: "ID token signature invalid",
					body: `<p>Signature verification failed: <code>${htmlEscape(verifyResult.error)}</code></p>`,
				}),
				400,
			);
		}
		const idTokenPayload = verifyResult.value;

		// Post-signature claim checks (jose already verified iss/aud/exp/nbf; we
		// still need to check nonce, which is OIDC-specific and not part of jose's
		// generic claim set).
		const claimErrors: string[] = [];
		if (idTokenPayload.nonce !== expectedNonce) {
			claimErrors.push("nonce mismatch");
		}

		// Trust chain that authorized this flow — reuse the discovery already performed
		// for token endpoint + jwks resolution (avoid a second outbound resolution pass).
		const chain: ReadonlyArray<{ iss: string; sub: string }> =
			opDiscovery.trustChain.statements.map((s) => ({
				iss: String(s.payload.iss ?? ""),
				sub: String(s.payload.sub ?? ""),
			}));

		return c.html(
			renderResultPage({
				ok: claimErrors.length === 0,
				title:
					claimErrors.length === 0
						? "Signed in successfully"
						: "Signed in (claim validation issues)",
				body: `
<h2>ID Token (decoded)</h2>
<pre>${htmlEscape(JSON.stringify(idTokenPayload, null, 2))}</pre>
${
	claimErrors.length === 0
		? "<p><strong>All federation-derived claim checks passed.</strong></p>"
		: `<h3>Claim issues</h3><ul>${claimErrors.map((e) => `<li><code>${htmlEscape(e)}</code></li>`).join("")}</ul>`
}
<h2>Trust chain</h2>
<p><small>Every signature below was verified in real time during your sign-in &mdash; before the OP accepted the Request Object and before any OIDC step ran. This chain <em>is</em> the registration.</small></p>
<ol>${chain.map((s) => `<li><code>${htmlEscape(s.iss)} → ${htmlEscape(s.sub)}</code></li>`).join("")}</ol>
`,
			}),
		);
	});

	// ── Hosted Request Object (request_uri delivery) ─────────────────────────
	app.get("/request-object/:id", (c) => {
		const id = c.req.param("id");
		pruneRequestObjectStore(requestObjectStore);
		const entry = requestObjectStore.get(id);
		if (!entry || entry.expiresAt < Date.now()) {
			return c.json(
				{
					error: "not_found",
					error_description: "Request Object not found or expired.",
					entity_id: entityId,
					entity_type: "demo-rp",
				},
				404,
			);
		}
		// Single-use: evict immediately so the JWT cannot be replayed.
		requestObjectStore.delete(id);
		return new Response(entry.jwt, {
			status: 200,
			headers: {
				"content-type": "application/oauth-authz-req+jwt",
				"cache-control": "no-store",
			},
		});
	});

	// ── Unified JSON envelope ────────────────────────────────────────────────
	app.notFound((c) =>
		c.json(
			{
				error: "not_found",
				error_description: "Path not handled by this demo RP.",
				entity_id: entityId,
				entity_type: "demo-rp",
			},
			404,
		),
	);

	app.onError((err, c) => {
		console.error(`[demo-rp:${entityId}] error: ${err.message}`);
		return c.json(
			{
				error: "server_error",
				error_description: "Internal error",
				entity_id: entityId,
				entity_type: "demo-rp",
			},
			500,
		);
	});

	return app;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie signing — HMAC-SHA256
// ─────────────────────────────────────────────────────────────────────────────

function deriveCookieSecret(signingKey: JWK): Buffer {
	// Derive a deterministic but key-bound secret from the JWK private fields.
	const seed = JSON.stringify({
		k: signingKey.kid ?? "",
		d: signingKey.d ?? "",
		x: signingKey.x ?? "",
		y: signingKey.y ?? "",
	});
	return crypto.createHash("sha256").update(seed).digest();
}

function signValue(value: string, secret: Buffer): string {
	const sig = crypto.createHmac("sha256", secret).update(value).digest("base64url");
	return `${value}.${sig}`;
}

function unsignValue(signed: string, secret: Buffer): string | undefined {
	const idx = signed.lastIndexOf(".");
	if (idx <= 0) return undefined;
	const value = signed.slice(0, idx);
	const sig = signed.slice(idx + 1);
	const expected = crypto.createHmac("sha256", secret).update(value).digest("base64url");
	if (sig.length !== expected.length) return undefined;
	if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return undefined;
	return value;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify the OP's signature on an ID token against the OP's federation-resolved jwks.
 *
 * We use jose directly (rather than `@oidfed/core/verifyEntityStatement`) because
 * node-oidc-provider emits id_tokens without a `typ` header, while
 * `verifyEntityStatement` requires an exact typ match. Returns a `Result`-shaped
 * tuple so the call site can render an error page deterministically without
 * exception-handling glue.
 *
 * Exported solely for direct testing of the verification contract — callers in
 * production should always go through the /callback handler.
 */
export async function verifyOpSignedIdToken(
	idToken: string,
	opJwks: { keys: JWK[] },
	opEntityId: string,
	clientId: string,
): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; error: string }> {
	try {
		const keyset = jose.createLocalJWKSet({
			keys: opJwks.keys as unknown as jose.JWK[],
		});
		const verified = await jose.jwtVerify(idToken, keyset, {
			issuer: opEntityId,
			audience: clientId,
			algorithms: ["ES256"],
		});
		return { ok: true, value: verified.payload as Record<string, unknown> };
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : "verification failed" };
	}
}

function pruneRequestObjectStore(cache: Map<string, { jwt: string; expiresAt: number }>): void {
	const now = Date.now();
	for (const [k, v] of cache) {
		if (v.expiresAt < now) cache.delete(k);
	}
}

function pruneFlowCache(cache: Map<string, FlowState>): void {
	const now = Date.now();
	for (const [k, v] of cache) {
		if (v.expiresAt < now) cache.delete(k);
	}
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

interface JsonErrorContext {
	json: (body: object, status?: number) => Response;
}

function jsonError(c: JsonErrorContext, code: string, description: string, status = 400): Response {
	return c.json(
		{
			error: code,
			error_description: description,
		},
		status,
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML templates — plain, no CSS, mirrors the panva/node-oidc-provider example shape.
// ─────────────────────────────────────────────────────────────────────────────

function renderLandingPage(opts: {
	entityId: string;
	opEntityId: string;
	registrationMode: "automatic" | "explicit";
	requestDelivery: RequestDelivery;
}): string {
	const callout =
		opts.registrationMode === "automatic"
			? renderAutomaticCallout(opts.requestDelivery)
			: renderExplicitCallout();
	return `<!doctype html><html lang=en><head><meta charset=utf-8><title>${htmlEscape(opts.entityId)}</title></head>
<body>
<h1>${htmlEscape(opts.entityId)}</h1>
<p>Registration mode: <code>${htmlEscape(opts.registrationMode)}</code>${
		opts.registrationMode === "automatic"
			? ` &middot; delivery: <code>${htmlEscape(opts.requestDelivery)}</code>`
			: ""
	}</p>
<p>OP: <code>${htmlEscape(opts.opEntityId)}</code></p>
<p><a href="/start-login"><strong>Sign in via OP →</strong></a></p>
${callout}
<p><small>Demo RP. <a href="/.well-known/openid-federation">Entity Configuration</a></small></p>
</body></html>`;
}

function renderAutomaticCallout(delivery: RequestDelivery): string {
	const deliveryLine =
		delivery === "form_post"
			? "submit a signed Request Object via HTTP POST body (no URL ceiling)"
			: delivery === "query"
				? "redirect to the OP with the signed Request Object in the <code>?request=</code> query parameter"
				: delivery === "request_uri"
					? "host the signed Request Object at a one-time URL and pass <code>?request_uri=</code> to the OP"
					: "POST the signed Request Object to the OP's <code>pushed_authorization_request_endpoint</code>, then redirect with the issued <code>urn:</code> request URI";
	return `<h2>What happens when you click</h2>
<ol>
<li>This RP signs a <strong>Request Object</strong> JWT whose JWS header embeds the RP&rsquo;s trust chain (this RP &rarr; Trust Anchor).</li>
<li>The RP will ${deliveryLine}.</li>
<li>The OP validates the chain against its own Trust Anchor, verifies the Request Object signature against the RP key resolved from the chain, then proceeds to the OIDC code flow.</li>
</ol>
<p><strong>No pre-registration step.</strong> Trust is established in-band by the chain you can inspect below.</p>`;
}

function renderExplicitCallout(): string {
	return `<h2>What happens when you click</h2>
<ol>
<li>This RP signs an <strong>Entity Configuration</strong> JWT and POSTs it to the OP&rsquo;s <code>federation_registration_endpoint</code>.</li>
<li>The OP validates the trust chain, mints a client registration, and returns a signed <em>Explicit Registration Response</em> Entity Statement containing the assigned <code>client_id</code> (and optional <code>client_secret</code>).</li>
<li>The RP redirects the user-agent to <code>/auth?client_id=&hellip;</code> &mdash; a plain OIDC authorization request, <strong>no Request Object</strong>, no embedded chain.</li>
</ol>
<p><strong>One round-trip ahead of the auth request</strong> exchanges the federation primitives for a stable client_id, then it&rsquo;s standard OIDC.</p>`;
}

function renderAutoSubmitForm(action: string, fields: Record<string, string>): string {
	const inputs = Object.entries(fields)
		.map(
			([name, value]) =>
				`<input type="hidden" name="${htmlEscape(name)}" value="${htmlEscape(value)}">`,
		)
		.join("");
	return `<!doctype html><html lang=en><head><meta charset=utf-8><title>Continue</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="${htmlEscape(action)}">
${inputs}
<noscript><button type="submit">Continue to sign-in</button></noscript>
</form>
</body></html>`;
}

function renderResultPage(opts: { ok: boolean; title: string; body: string }): string {
	return `<!doctype html><html lang=en><head><meta charset=utf-8><title>${htmlEscape(opts.title)}</title></head>
<body>
<h1>${htmlEscape(opts.title)}</h1>
${opts.body}
<p><a href="/">Back</a></p>
</body></html>`;
}
