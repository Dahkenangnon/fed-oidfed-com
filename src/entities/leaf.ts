import type { LeafEntity } from "@oidfed/leaf";
import { Hono } from "hono";
import { cors } from "hono/cors";

/**
 * Hono request listener for a leaf entity. Exposes a single endpoint —
 * `/.well-known/openid-federation` — which serves the entity's signed
 * Entity Configuration via `leaf.handler()`.
 *
 * Used for federation-only RPs (RPs that do not run OIDC themselves). Leaf OPs
 * use the richer factory in `./op.ts` instead.
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/participants/leaf-app.ts
 */
export function createLeafHonoApp(leaf: LeafEntity, entityId: string): Hono {
	const app = new Hono();

	app.use(
		"*",
		cors({
			origin: "*",
			allowMethods: ["GET", "OPTIONS"],
			allowHeaders: ["Content-Type", "Accept"],
			maxAge: 86400,
		}),
	);

	const leafHandler = leaf.handler();

	app.get("/.well-known/openid-federation", async () => {
		const request = new Request(`${entityId}/.well-known/openid-federation`, { method: "GET" });
		return leafHandler(request);
	});

	return app;
}
