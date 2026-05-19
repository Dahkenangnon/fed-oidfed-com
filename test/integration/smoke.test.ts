import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootstrapFederation } from "../../src/bootstrap.js";
import { type ListenerRegistry, resolveListener } from "../../src/registry.js";
import { topologies } from "../../src/topologies/index.js";

interface Harness {
	server: http.Server;
	port: number;
	registry: ListenerRegistry;
}

let harness: Harness;

beforeAll(async () => {
	const { listeners } = await bootstrapFederation(topologies);
	const server = http.createServer((req, res) => {
		const listener = resolveListener(listeners, req.headers.host);
		if (!listener) {
			res.writeHead(404).end();
			return;
		}
		listener(req, res);
	});
	const port = await new Promise<number>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			resolve((server.address() as AddressInfo).port);
		});
	});
	harness = { server, port, registry: listeners };
});

afterAll(async () => {
	await new Promise<void>((resolve, reject) => {
		harness.server.close((err) => (err ? reject(err) : resolve()));
	});
});

interface RequestResult {
	status: number;
	headers: http.IncomingHttpHeaders;
	body: string;
}

// Node's fetch() forbids overriding the Host header; use raw http.request so the
// vhost dispatcher actually sees the intended hostname.
function request(
	host: string,
	path: string,
	extraHeaders: Record<string, string> = {},
): Promise<RequestResult> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: "127.0.0.1",
				port: harness.port,
				path,
				method: "GET",
				headers: { Host: host, ...extraHeaders },
			},
			(res) => {
				let body = "";
				res.setEncoding("utf8");
				res.on("data", (chunk) => {
					body += chunk;
				});
				res.on("end", () => {
					resolve({ status: res.statusCode ?? 0, headers: res.headers, body });
				});
			},
		);
		req.on("error", reject);
		req.end();
	});
}

const TA_HOSTS = [
	"ta.single.fed.oidfed.com",
	"ta.hier.fed.oidfed.com",
	"ta-gov.multi.fed.oidfed.com",
	"ta-x.xfed.fed.oidfed.com",
	"ta.constr.fed.oidfed.com",
	"ta.policy.fed.oidfed.com",
];

const ALIASES = ["single.fed.oidfed.com", "minimal.fed.oidfed.com"];

describe("federation deployment smoke", () => {
	it("registers every entity across all topologies as a vhost", () => {
		// 34 entities + 2 aliases (single, minimal) = 36 vhosts
		expect(harness.registry.size).toBe(36);
	});

	it.each(TA_HOSTS)("serves an entity-configuration JWT for TA %s", async (host) => {
		const res = await request(host, "/.well-known/openid-federation");
		expect(res.status).toBe(200);
		const contentType = (res.headers["content-type"] ?? "") as string;
		expect(contentType).toContain("application/entity-statement+jwt");
		expect(res.body.split(".")).toHaveLength(3);
	});

	it.each(ALIASES)("alias %s resolves to the single-anchor TA", async (alias) => {
		const res = await request(alias, "/.well-known/openid-federation");
		expect(res.status).toBe(200);
	});

	it("returns 404 for an unknown host", async () => {
		const res = await request("nowhere.fed.oidfed.com", "/.well-known/openid-federation");
		expect(res.status).toBe(404);
	});

	it("sends CORS headers on federation endpoints", async () => {
		const res = await request("ta.single.fed.oidfed.com", "/.well-known/openid-federation", {
			Origin: "https://example.com",
		});
		expect(res.headers["access-control-allow-origin"]).toBeTruthy();
	});
});
