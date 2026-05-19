/**
 * Process entry — bootstrap all topologies, log the resulting vhost map,
 * and start the Host-header-dispatching HTTP server. `PORT` and `HOST` are
 * the only env knobs read here; key-persistence overrides live in `./persistence.ts`.
 */

import { bootstrapFederation } from "./bootstrap.js";
import { startVhostServer } from "./server.js";
import { topologies } from "./topologies/index.js";

const PORT = Number(process.env.PORT ?? "3000");
const HOST = process.env.HOST ?? "127.0.0.1";

async function main(): Promise<void> {
	const start = Date.now();
	const { listeners, entityCount } = await bootstrapFederation(topologies);
	const elapsed = ((Date.now() - start) / 1000).toFixed(2);

	console.log(
		`[fed-oidfed-com] bootstrapped ${entityCount} entities across ${topologies.length} topologies in ${elapsed}s`,
	);
	console.log(`[fed-oidfed-com] vhost map: ${listeners.size} hostnames registered`);
	for (const host of [...listeners.keys()].sort()) {
		console.log(`  · ${host}`);
	}

	await startVhostServer({ port: PORT, host: HOST, registry: listeners });
	console.log(`[fed-oidfed-com] listening on http://${HOST}:${PORT}`);
}

main().catch((err) => {
	console.error("[fed-oidfed-com] fatal:", err);
	process.exit(1);
});
