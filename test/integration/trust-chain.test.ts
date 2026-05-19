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

function request(host: string, path: string): Promise<RequestResult> {
	return new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: "127.0.0.1",
				port: harness.port,
				path,
				method: "GET",
				headers: { Host: host },
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

function decodeJwtPayload(jwt: string): Record<string, unknown> {
	const [, payload] = jwt.split(".");
	if (!payload) throw new Error("Invalid JWT shape");
	return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("trust chain resolution shape (single-anchor)", () => {
	it("op entity configuration declares ta as authority hint", async () => {
		const res = await request("op.single.fed.oidfed.com", "/.well-known/openid-federation");
		expect(res.status).toBe(200);
		const payload = decodeJwtPayload(res.body);
		expect(payload.iss).toBe("https://op.single.fed.oidfed.com");
		expect(payload.sub).toBe("https://op.single.fed.oidfed.com");
		const hints = payload.authority_hints as string[] | undefined;
		expect(hints).toContain("https://ta.single.fed.oidfed.com");
	});

	it("ta federation_fetch returns a subordinate statement for op", async () => {
		const sub = encodeURIComponent("https://op.single.fed.oidfed.com");
		const res = await request("ta.single.fed.oidfed.com", `/federation_fetch?sub=${sub}`);
		expect(res.status).toBe(200);
		const payload = decodeJwtPayload(res.body);
		expect(payload.iss).toBe("https://ta.single.fed.oidfed.com");
		expect(payload.sub).toBe("https://op.single.fed.oidfed.com");
	});
});
