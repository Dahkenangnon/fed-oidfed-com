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

	// Unified JSON envelope for unhandled paths — same shape as the other participants.
	app.notFound((c) =>
		c.json(
			{
				error: "not_found",
				error_description: "Path not handled by this leaf entity.",
				entity_id: entityId,
				entity_type: "leaf-rp",
			},
			404,
		),
	);

	app.onError((err, c) => {
		console.error(`[leaf:${entityId}] error: ${err.message}`);
		return c.json(
			{
				error: "server_error",
				error_description: "Internal error",
				entity_id: entityId,
				entity_type: "leaf-rp",
			},
			500,
		);
	});

	return app;
}
