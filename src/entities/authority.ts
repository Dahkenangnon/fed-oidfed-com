import type { AuthorityServer } from "@oidfed/authority";
import { Hono } from "hono";
import { cors } from "hono/cors";

/**
 * Hono request listener for a Trust Anchor or Intermediate Authority entity.
 *
 * Hono port of the Express factory at the corresponding e2e participant —
 * same `authority.handler()` wiring, same incoming-URL canonicalization to the
 * public entityId origin, identical 64KB body handling expectations (enforced
 * upstream by the `AuthorityServer` handler itself).
 *
 * Staying in Web-API land (Request/Response) keeps this factory portable to
 * workerd/Deno without code changes; the Node-only OP factory in `./op.ts`
 * uses Express because `node-oidc-provider` depends on Node streams + koa-compose.
 *
 * CORS is open (`*`) so browser-based federation explorers can fetch
 * federation endpoints cross-origin.
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/participants/authority-app.ts
 */
export function createAuthorityHonoApp(authority: AuthorityServer, entityId: string): Hono {
	const app = new Hono();

	app.use(
		"*",
		cors({
			origin: "*",
			allowMethods: ["GET", "POST", "OPTIONS"],
			allowHeaders: ["Content-Type", "Accept"],
			maxAge: 86400,
		}),
	);

	const federationHandler = authority.handler();

	app.all("*", async (c) => {
		// Rewrite request URL to use the entity's canonical origin so the federation handler
		// receives the public-facing URL (not internal 127.0.0.1:3000).
		const incoming = new URL(c.req.url);
		const canonical = new URL(entityId);
		const url = `${canonical.origin}${incoming.pathname}${incoming.search}`;

		const hasBody = c.req.method !== "GET" && c.req.method !== "HEAD";
		const init: RequestInit = {
			method: c.req.method,
			headers: c.req.raw.headers,
		};
		if (hasBody) {
			init.body = await c.req.raw.arrayBuffer();
		}
		const request = new Request(url, init);

		return federationHandler(request);
	});

	return app;
}
