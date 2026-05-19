/**
 * Single Node HTTP listener that dispatches incoming requests to the right
 * per-entity request listener based on the `Host` header. Production
 * deployments terminate TLS at a reverse proxy and forward the original
 * `Host` so this dispatcher sees the canonical entityId hostname.
 *
 * Same pattern as `https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/helpers/federation-server.ts`.
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/helpers/federation-server.ts
 */

import http from "node:http";
import { type ListenerRegistry, resolveListener } from "./registry.js";

export interface ServerOptions {
	port: number;
	host: string;
	registry: ListenerRegistry;
}

export interface RunningServer {
	close(): Promise<void>;
}

export function startVhostServer(opts: ServerOptions): Promise<RunningServer> {
	return new Promise((resolve, reject) => {
		const server = http.createServer((req, res) => {
			const listener = resolveListener(opts.registry, req.headers.host);
			if (!listener) {
				const host = (req.headers.host ?? "").replace(/:\d+$/, "");
				res.writeHead(404, { "Content-Type": "text/plain" });
				res.end(`No federation entity bound to host: ${host}\n`);
				return;
			}
			listener(req, res);
		});

		server.on("error", reject);

		server.listen(opts.port, opts.host, () => {
			resolve({
				close() {
					return new Promise((r, j) => {
						server.close((err) => (err ? j(err) : r()));
					});
				},
			});
		});
	});
}
