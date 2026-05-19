import type { AuthorityServer } from "@oidfed/authority";
import type { EntityId, HttpClient, TrustAnchorSet } from "@oidfed/core";
import { InMemoryJtiStore } from "@oidfed/core";
import { processAutomaticRegistration } from "@oidfed/oidc";
import cors from "cors";
import express, { type Express } from "express";
import Provider from "oidc-provider";

export interface OpExpressAppConfig {
	authority: AuthorityServer;
	entityId: string;
	trustAnchors: TrustAnchorSet;
	/**
	 * Outbound HTTP client for the OP's federation lookups (resolving the RP's
	 * trust chain during `processAutomaticRegistration`). Defaults to the global
	 * `fetch`. Override for hermetic integration tests, request-throttling
	 * proxies, or fetch-policy enforcement (allowed-hosts, CIDR blocks, etc.).
	 */
	httpClient?: HttpClient;
}

/**
 * Express factory for a leaf OP — mounts the federation endpoint surface
 * alongside a `node-oidc-provider` instance in the same app.
 *
 * Stays on Express because `node-oidc-provider` is Node-only (depends on Node
 * streams and koa-compose). The federation endpoint subset (`federation_fetch`,
 * `federation_list`, `federation_resolve`, `federation_registration`,
 * `federation_trust_mark*`) is mounted via the upstream `authority.handler()`.
 *
 * Two OIDC integration points:
 *
 *   • `/auth` is intercepted to detect an inbound Request Object (`?request=`)
 *     and run it through `processAutomaticRegistration` before forwarding to
 *     `node-oidc-provider`. On a validation failure, return the canonical OIDC
 *     error JSON. The Request Object branch is the OP-side half of automatic
 *     registration; the RP-side half lives in `@oidfed/oidc`'s
 *     `automaticRegistration`.
 *
 *   • `/federation_registration` is the OP-side of explicit registration.
 *     Requests are forwarded to `authority.handler()`, which uses the
 *     registration handler built into `@oidfed/authority` (see
 *     `https://github.com/Dahkenangnon/oidfed/blob/main/packages/authority/src/endpoints/registration.ts`). The `@oidfed/oidc`
 *     `processExplicitRegistration` export is a separate, lower-level entry
 *     point for callers who do not use the authority handler; this app does
 *     not need it.
 *
 * The OIDC issuer claim is set to the public entityId, which MUST match the
 * subdomain that dispatches to this app (e.g. `https://op.single.fed.oidfed.com`).
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/participants/openid-provider-app.ts
 */
export function createOpExpressApp(config: OpExpressAppConfig): Express {
	const { authority, entityId, trustAnchors, httpClient = fetch } = config;
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

	const jtiStore = new InMemoryJtiStore();
	const federationHandler = authority.handler();

	const oidc = new Provider(entityId, {
		clients: [],
		findAccount: async (_ctx: unknown, id: string) => ({
			accountId: id,
			async claims() {
				return { sub: id };
			},
		}),
		features: {
			registration: { enabled: false },
		},
	});
	oidc.proxy = true;

	app.all("/.well-known/openid-federation", async (req, res) => {
		const url = new URL(req.originalUrl, entityId);
		const request = new Request(url.toString(), { method: "GET" });
		const response = await federationHandler(request);
		res.status(response.status);
		for (const [key, value] of response.headers) {
			res.setHeader(key, value);
		}
		res.send(await response.text());
	});

	const FEDERATION_PATHS = [
		"/federation_fetch",
		"/federation_list",
		"/federation_resolve",
		"/federation_registration",
		"/federation_trust_mark",
		"/federation_trust_mark_status",
		"/federation_trust_mark_list",
	];
	for (const path of FEDERATION_PATHS) {
		app.all(path, async (req, res) => {
			const url = new URL(req.originalUrl, entityId);
			const hasBody = req.method !== "GET" && req.method !== "HEAD";
			let body: BodyInit | undefined;
			if (hasBody) {
				if (Buffer.isBuffer(req.body)) {
					body = new Uint8Array(req.body);
				} else if (typeof req.body === "object" && req.body !== null) {
					body = new URLSearchParams(req.body as Record<string, string>).toString();
				}
			}
			const request = new Request(url.toString(), {
				method: req.method,
				headers: req.headers as Record<string, string>,
				...(body !== undefined ? { body } : {}),
			});
			const response = await federationHandler(request);
			res.status(response.status);
			for (const [key, value] of response.headers) {
				res.setHeader(key, value);
			}
			res.send(await response.text());
		});
	}

	// Automatic registration: intercept /auth with ?request= JWT
	app.get("/auth", async (req, res, next) => {
		const requestJwt = req.query.request as string | undefined;
		if (requestJwt) {
			const result = await processAutomaticRegistration(requestJwt, trustAnchors, {
				opEntityId: entityId as EntityId,
				jtiStore,
				httpClient,
			});
			if (!result.ok) {
				res.status(400).json({
					error: result.error.code,
					error_description: result.error.description,
				});
				return;
			}
		}
		const handler = oidc.callback() as express.RequestHandler;
		return handler(req, res, next);
	});

	app.use("/", oidc.callback() as express.RequestHandler);

	return app;
}
