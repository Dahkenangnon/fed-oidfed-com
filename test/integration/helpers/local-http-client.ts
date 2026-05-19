/**
 * In-process HttpClient — wraps `http.request` so the @oidfed library can fetch
 * federation endpoints from the running test server without DNS resolution or TLS.
 *
 * Why not plain `fetch`? Federation entityIds are canonical `https://*.fed.oidfed.com`
 * URLs without ports. `fetch()` would try to resolve those public hostnames over the
 * real network. We rewrite every URL to `http://127.0.0.1:${testPort}` while preserving
 * the original hostname in the `Host` header so the in-process vhost dispatcher
 * (`src/server.ts`) routes correctly. `fetch()` forbids setting the `Host` header,
 * so we drop down to `http.request` directly.
 */

import http, { type IncomingMessage } from "node:http";
import type { HttpClient } from "@oidfed/core";

export function localHttpClient(testPort: number): HttpClient {
	return async (input, init) => {
		const { url, method, headers, body } = await normalizeRequest(input, init);
		const target = new URL(url);

		const requestHeaders: Record<string, string> = {
			...Object.fromEntries(headers.entries()),
			host: target.host,
		};

		return new Promise<Response>((resolve, reject) => {
			const req = http.request(
				{
					host: "127.0.0.1",
					port: testPort,
					method,
					path: `${target.pathname}${target.search}`,
					headers: requestHeaders,
				},
				(res: IncomingMessage) => {
					const chunks: Buffer[] = [];
					res.on("data", (chunk: Buffer) => chunks.push(chunk));
					res.on("end", () => {
						const responseBody = Buffer.concat(chunks);
						const responseHeaders = new Headers();
						for (const [k, v] of Object.entries(res.headers)) {
							if (Array.isArray(v)) {
								for (const item of v) responseHeaders.append(k, item);
							} else if (v !== undefined) {
								responseHeaders.set(k, v);
							}
						}
						resolve(
							new Response(responseBody, {
								status: res.statusCode ?? 500,
								statusText: res.statusMessage ?? "",
								headers: responseHeaders,
							}),
						);
					});
					res.on("error", reject);
				},
			);

			req.on("error", reject);
			if (body !== undefined) req.write(body);
			req.end();
		});
	};
}

async function normalizeRequest(
	input: string | URL | Request,
	init?: RequestInit,
): Promise<{ url: string; method: string; headers: Headers; body: Buffer | undefined }> {
	if (input instanceof Request) {
		const buffer = await input.arrayBuffer();
		return {
			url: input.url,
			method: input.method,
			headers: new Headers(input.headers),
			body: buffer.byteLength > 0 ? Buffer.from(buffer) : undefined,
		};
	}

	const url = typeof input === "string" ? input : input.toString();
	const method = init?.method ?? "GET";
	const headers = new Headers(init?.headers ?? {});
	const body = init?.body !== undefined ? coerceBody(init.body) : undefined;

	return { url, method, headers, body };
}

function coerceBody(body: BodyInit): Buffer {
	if (typeof body === "string") return Buffer.from(body, "utf8");
	if (body instanceof ArrayBuffer) return Buffer.from(body);
	if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
	if (body instanceof URLSearchParams) return Buffer.from(body.toString(), "utf8");
	throw new Error(`localHttpClient: unsupported body type ${Object.prototype.toString.call(body)}`);
}
