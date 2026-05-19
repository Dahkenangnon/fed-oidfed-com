/**
 * End-to-end OIDC flow over OpenID Federation 1.0 — visible-from-the-browser path.
 *
 * Cases:
 *   1. Automatic happy path  — RP1 → OP /auth → /interaction → login → consent →
 *                              callback → ID token bound to the federation.
 *   2. Explicit happy path   — RP2 same shape via /federation_registration first.
 *   3. Tampered Request Obj  — /auth returns JSON 400, never redirects.
 *   4. Callback state guard  — /callback with mismatched state → 400.
 *   5. Unified / envelope    — every participant returns the JSON envelope.
 */

import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { signEntityStatement, entityId as toEntityId } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import * as jose from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type BootstrapResult, bootstrapFederation } from "../../src/bootstrap.js";
import { verifyOpSignedIdToken } from "../../src/entities/demo-rp.js";
import { resolveListener } from "../../src/registry.js";
import { singleAnchorTopology } from "../../src/topologies/single-anchor.js";
import { localHttpClient } from "./helpers/local-http-client.js";

const TA_ID = "https://ta.single.fed.oidfed.com";
const OP_ID = "https://op.single.fed.oidfed.com";
const RP1_ID = "https://rp1.single.fed.oidfed.com";
const RP2_ID = "https://rp2.single.fed.oidfed.com";

interface Harness {
	server: http.Server;
	port: number;
	bootstrap: BootstrapResult;
}

let harness: Harness;

beforeAll(async () => {
	const server = http.createServer();
	const port = await new Promise<number>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			resolve((server.address() as AddressInfo).port);
		});
	});
	const httpClient = localHttpClient(port);
	const bootstrap = await bootstrapFederation([singleAnchorTopology], { httpClient });

	server.on("request", (req, res) => {
		const listener = resolveListener(bootstrap.listeners, req.headers.host);
		if (!listener) {
			res.writeHead(404).end();
			return;
		}
		listener(req, res);
	});

	harness = { server, port, bootstrap };
});

afterAll(async () => {
	await new Promise<void>((resolve, reject) => {
		harness.server.close((err) => (err ? reject(err) : resolve()));
	});
});

interface RawResponse {
	status: number;
	headers: http.IncomingHttpHeaders;
	body: string;
}

class CookieJar {
	private byHost = new Map<string, Map<string, string>>();
	ingest(host: string, setCookies: string | string[] | undefined): void {
		if (!setCookies) return;
		const arr = Array.isArray(setCookies) ? setCookies : [setCookies];
		const bucket = this.byHost.get(host) ?? new Map<string, string>();
		for (const raw of arr) {
			const semi = raw.indexOf(";");
			const pair = semi < 0 ? raw : raw.slice(0, semi);
			const eq = pair.indexOf("=");
			if (eq <= 0) continue;
			bucket.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
		}
		this.byHost.set(host, bucket);
	}
	header(host: string): string | undefined {
		const bucket = this.byHost.get(host);
		if (!bucket || bucket.size === 0) return undefined;
		return [...bucket.entries()].map(([n, v]) => `${n}=${v}`).join("; ");
	}
}

function send(
	jar: CookieJar,
	method: "GET" | "POST",
	host: string,
	path: string,
	body?: string,
): Promise<RawResponse> {
	return new Promise((resolve, reject) => {
		const headers: Record<string, string> = {
			Host: host,
			Accept: "text/html, application/json",
			// node-oidc-provider runs with proxy:true; in production nginx terminates
			// TLS and forwards this header. The integration server runs over HTTP, so
			// we surface the production header explicitly to unblock secure cookies.
			"X-Forwarded-Proto": "https",
		};
		if (body !== undefined) {
			headers["Content-Type"] = "application/x-www-form-urlencoded";
			headers["Content-Length"] = String(Buffer.byteLength(body));
		}
		const cookie = jar.header(host);
		if (cookie) headers.Cookie = cookie;

		const req = http.request(
			{ method, host: "127.0.0.1", port: harness.port, path, headers },
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (c: Buffer) => chunks.push(c));
				res.on("end", () => {
					jar.ingest(host, res.headers["set-cookie"]);
					resolve({
						status: res.statusCode ?? 0,
						headers: res.headers,
						body: Buffer.concat(chunks).toString("utf8"),
					});
				});
				res.on("error", reject);
			},
		);
		req.on("error", reject);
		if (body !== undefined) req.write(body);
		req.end();
	});
}

function urlParts(u: string): { host: string; path: string } {
	const url = new URL(u);
	return { host: url.host, path: `${url.pathname}${url.search}` };
}

async function followRedirects(
	jar: CookieJar,
	startHost: string,
	startPath: string,
	maxHops = 12,
): Promise<RawResponse> {
	let current = await send(jar, "GET", startHost, startPath);
	let hops = 0;
	while (
		(current.status === 301 || current.status === 302 || current.status === 303) &&
		hops < maxHops
	) {
		const loc = current.headers.location;
		if (typeof loc !== "string") break;
		const next = loc.startsWith("http") ? urlParts(loc) : { host: startHost, path: loc };
		current = await send(jar, "GET", next.host, next.path);
		hops += 1;
	}
	return current;
}

function extractAction(html: string, suffix: string): string | undefined {
	const re = new RegExp(`action=(\/interaction\/[^\\s>]+\/${suffix})`);
	return re.exec(html)?.[1];
}

describe("unified / envelope across non-RP participants", () => {
	// Demo RPs serve an HTML landing page at /; they are exempt from the
	// unified-404 expectation. See the next describe block for their dedicated tests.
	for (const target of [TA_ID, OP_ID]) {
		const hostname = new URL(target).host;
		it(`${hostname} returns the JSON envelope at /`, async () => {
			const jar = new CookieJar();
			const res = await send(jar, "GET", hostname, "/");
			expect(res.status).toBe(404);
			expect(res.headers["content-type"]).toMatch(/application\/json/);
			const body = JSON.parse(res.body) as Record<string, unknown>;
			expect(body.error).toBe("not_found");
			expect(typeof body.error_description).toBe("string");
			expect(body.entity_id).toBe(target);
			expect(typeof body.entity_type).toBe("string");
		});
	}
});

describe("demo RPs serve HTML at / and JSON envelope for unhandled paths", () => {
	for (const target of [RP1_ID, RP2_ID]) {
		const hostname = new URL(target).host;
		it(`${hostname} serves the landing page at /`, async () => {
			const jar = new CookieJar();
			const res = await send(jar, "GET", hostname, "/");
			expect(res.status).toBe(200);
			expect(res.headers["content-type"]).toMatch(/text\/html/);
			expect(res.body).toContain(target);
			expect(res.body).toContain("/start-login");
		});

		it(`${hostname} returns the JSON envelope for an unhandled path`, async () => {
			const jar = new CookieJar();
			const res = await send(jar, "GET", hostname, "/no-such-path");
			expect(res.status).toBe(404);
			expect(res.headers["content-type"]).toMatch(/application\/json/);
			const body = JSON.parse(res.body) as Record<string, unknown>;
			expect(body.error).toBe("not_found");
			expect(body.entity_id).toBe(target);
		});
	}
});

async function followInteractionChain(
	jar: CookieJar,
	startHost: string,
	startPath: string,
	formAction: "login" | "confirm",
	maxHops = 12,
): Promise<RawResponse> {
	let path = startPath;
	let host = startHost;
	for (let i = 0; i < maxHops; i += 1) {
		const res = await send(jar, "GET", host, path);
		if (res.status === 200) return res;
		if (res.status === 302 || res.status === 303) {
			const loc = res.headers.location as string | undefined;
			if (!loc) return res;
			const next = loc.startsWith("http") ? urlParts(loc) : { host, path: loc };
			host = next.host;
			path = next.path;
			continue;
		}
		// Unexpected status — surface for the caller's assertion.
		return res;
	}
	throw new Error(`followInteractionChain exceeded ${maxHops} hops looking for ${formAction} form`);
}

/**
 * Extract the action and hidden input fields of the first `<form>` in `html`.
 * The demo RP's auto-submit form is small and uses a stable template.
 */
function extractFormAction(html: string): string | undefined {
	const m = /action="([^"]+)"/.exec(html);
	return m?.[1];
}

function extractHiddenFields(html: string): Record<string, string> {
	const fields: Record<string, string> = {};
	const pattern = /<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"[^>]*>/gi;
	let match = pattern.exec(html);
	while (match !== null) {
		const name = match[1];
		const value = match[2];
		if (typeof name === "string") {
			fields[name] = value ?? "";
		}
		match = pattern.exec(html);
	}
	return fields;
}

async function continueAfterOpAuth(jar: CookieJar, authRes: RawResponse): Promise<RawResponse> {
	if (authRes.status !== 302 && authRes.status !== 303) {
		throw new Error(
			`Expected 30x from OP /auth, got ${authRes.status}: ${authRes.body.slice(0, 400)}`,
		);
	}

	// 3. Follow redirects to land on the login HTML form.
	const intLoc = authRes.headers.location as string;
	const intPath = intLoc.startsWith("http") ? urlParts(intLoc).path : intLoc;
	const loginPage = await followInteractionChain(jar, new URL(OP_ID).host, intPath, "login");
	if (loginPage.status !== 200) {
		throw new Error(
			`Expected login HTML, got ${loginPage.status}: ${loginPage.body.slice(0, 400)}`,
		);
	}
	const loginAction = extractAction(loginPage.body, "login");
	if (!loginAction) throw new Error(`No login form found: ${loginPage.body.slice(0, 400)}`);

	// 4. POST login, then follow redirects until we hit the consent prompt HTML.
	const loginPost = await send(jar, "POST", new URL(OP_ID).host, loginAction, "");
	if (loginPost.status !== 302 && loginPost.status !== 303) {
		throw new Error(`Expected 30x from /login, got ${loginPost.status}`);
	}
	const consentLoc = loginPost.headers.location as string;
	const consentPath = consentLoc.startsWith("http") ? urlParts(consentLoc).path : consentLoc;
	const consentPage = await followInteractionChain(
		jar,
		new URL(OP_ID).host,
		consentPath,
		"confirm",
	);
	if (consentPage.status !== 200) {
		throw new Error(
			`Expected consent HTML, got ${consentPage.status}: ${consentPage.body.slice(0, 400)}`,
		);
	}
	const confirmAction = extractAction(consentPage.body, "confirm");
	if (!confirmAction) throw new Error(`No confirm form found: ${consentPage.body.slice(0, 400)}`);

	// 5. POST confirm, follow all redirects (back via OP /auth resume → RP /callback).
	const confirmPost = await send(jar, "POST", new URL(OP_ID).host, confirmAction, "");
	if (confirmPost.status !== 302 && confirmPost.status !== 303) {
		throw new Error(`Expected 30x from /confirm, got ${confirmPost.status}`);
	}
	const finalLoc = confirmPost.headers.location as string;
	const final = await followRedirects(jar, new URL(OP_ID).host, urlParts(finalLoc).path);
	return final;
}

async function runFullOidcFlow(rpHost: string): Promise<RawResponse> {
	const jar = new CookieJar();

	// 1. Start login on the RP.
	const start = await send(jar, "GET", rpHost, "/start-login");

	// 2. Dispatch the request object to the OP /auth endpoint. Two shapes:
	//   • 302 Location: redirect to the OP (query / request_uri / par modes,
	//     and explicit-registration RPs).
	//   • 200 HTML form: an auto-submit form_post page — extract action +
	//     hidden inputs and POST them.
	let authRes: RawResponse;
	if (start.status === 302) {
		const opAuthUrl = start.headers.location as string;
		const opAuth = urlParts(opAuthUrl);
		authRes = await send(jar, "GET", opAuth.host, opAuth.path);
	} else if (
		start.status === 200 &&
		typeof start.headers["content-type"] === "string" &&
		start.headers["content-type"].includes("text/html")
	) {
		const action = extractFormAction(start.body);
		if (!action) {
			throw new Error(
				`Expected auto-submit form from /start-login, got: ${start.body.slice(0, 400)}`,
			);
		}
		const fields = extractHiddenFields(start.body);
		const opAction = urlParts(action);
		const formBody = new URLSearchParams(fields).toString();
		authRes = await send(jar, "POST", opAction.host, opAction.path, formBody);
	} else {
		throw new Error(
			`Unexpected /start-login response: status=${start.status}, content-type=${start.headers["content-type"] ?? "<none>"}`,
		);
	}

	return continueAfterOpAuth(jar, authRes);
}

describe("automatic OIDC flow (RP1)", () => {
	it("completes end-to-end and renders an ID token bound to the federation", async () => {
		const final = await runFullOidcFlow(new URL(RP1_ID).host);
		expect(final.status).toBe(200);
		expect(final.body).toContain("ID Token (decoded)");
		expect(final.body).toContain(OP_ID);
		expect(final.body).toContain(RP1_ID);
		expect(final.body).toContain("alice@example.com");
	}, 30_000);
});

describe("explicit OIDC flow (RP2)", () => {
	it("completes end-to-end via the explicit-registration path", async () => {
		const final = await runFullOidcFlow(new URL(RP2_ID).host);
		expect(final.status).toBe(200);
		expect(final.body).toContain("ID Token (decoded)");
		expect(final.body).toContain(OP_ID);
		expect(final.body).toContain(RP2_ID);
		expect(final.body).toContain("alice@example.com");
	}, 30_000);
});

describe("automatic OIDC flow — every delivery mode", () => {
	// Per-mode harness: spin up a fresh federation with RP1's protocolDelivery
	// pinned to the mode under test. The shared `harness` exercises the default
	// (form_post); these add the other three.
	const modes = ["query", "request_uri", "par"] as const;

	for (const mode of modes) {
		it(`completes end-to-end with delivery mode "${mode}"`, async () => {
			const modeServer = http.createServer();
			const modePort = await new Promise<number>((resolve) => {
				modeServer.listen(0, "127.0.0.1", () => {
					resolve((modeServer.address() as AddressInfo).port);
				});
			});
			const modeHttpClient = localHttpClient(modePort);
			const patchedTopology = {
				...singleAnchorTopology,
				entities: singleAnchorTopology.entities.map((e) =>
					e.id === RP1_ID ? { ...e, protocolDelivery: mode } : e,
				),
			};
			const modeBootstrap = await bootstrapFederation([patchedTopology], {
				httpClient: modeHttpClient,
			});
			modeServer.on("request", (req, res) => {
				const listener = resolveListener(modeBootstrap.listeners, req.headers.host);
				if (!listener) {
					res.writeHead(404).end();
					return;
				}
				listener(req, res);
			});

			// Per-mode harness needs its own send() — temporarily override the port.
			const originalPort = harness.port;
			const originalServer = harness.server;
			harness = { server: modeServer, port: modePort, bootstrap: modeBootstrap };
			try {
				const final = await runFullOidcFlow(new URL(RP1_ID).host);
				expect(final.status).toBe(200);
				expect(final.body).toContain("ID Token (decoded)");
				expect(final.body).toContain(OP_ID);
				expect(final.body).toContain(RP1_ID);
				expect(final.body).toContain("alice@example.com");
			} finally {
				harness = { server: originalServer, port: originalPort, bootstrap: harness.bootstrap };
				await new Promise<void>((resolve, reject) =>
					modeServer.close((err) => (err ? reject(err) : resolve())),
				);
			}
		}, 30_000);
	}
});

describe("OP guards", () => {
	it("a tampered Request Object yields JSON 400 (never redirect to redirect_uri)", async () => {
		const jar = new CookieJar();
		const res = await send(
			jar,
			"GET",
			new URL(OP_ID).host,
			`/auth?request=eyJhbGciOiJFUzI1NiJ9.aGVsbG8.bm9wZQ&client_id=${encodeURIComponent(RP1_ID)}`,
		);
		expect(res.status).toBe(400);
		expect(res.headers["content-type"]).toMatch(/application\/json/);
		const body = JSON.parse(res.body) as Record<string, unknown>;
		expect(typeof body.error).toBe("string");
		expect(typeof body.error_description).toBe("string");
		expect(body.entity_id).toBe(OP_ID);
	});

	it("a callback with state cookie mismatch yields 400", async () => {
		const jar = new CookieJar();
		const res = await send(jar, "GET", new URL(RP1_ID).host, "/callback?code=fake&state=bogus");
		expect(res.status).toBe(400);
		expect(res.headers["content-type"]).toMatch(/application\/json/);
		const body = JSON.parse(res.body) as Record<string, unknown>;
		expect(body.error).toBe("invalid_state");
	});
});

describe("ID token signature verification", () => {
	it("accepts an id_token signed by the OP", async () => {
		const httpClient = localHttpClient(harness.port);
		const discovery = await discoverEntity(toEntityId(OP_ID), harness.bootstrap.trustAnchors, {
			httpClient,
		});
		const opJwks = discovery.trustChain.statements[0]?.payload.jwks as
			| { keys: Array<Record<string, unknown>> }
			| undefined;
		expect(opJwks?.keys?.length).toBeGreaterThan(0);

		const opKeys = harness.bootstrap.entityKeys.get(OP_ID);
		expect(opKeys).toBeDefined();
		const opPrivateJwk = opKeys?.signing as unknown as Record<string, unknown>;
		const opCryptoKey = await jose.importJWK(opPrivateJwk as jose.JWK, "ES256");

		const idToken = await new jose.SignJWT({
			sub: "alice@example.com",
			nonce: "n-test",
		})
			.setProtectedHeader({ alg: "ES256", kid: opPrivateJwk.kid as string })
			.setIssuer(OP_ID)
			.setAudience(RP1_ID)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(opCryptoKey as Parameters<typeof jose.SignJWT.prototype.sign>[0]);

		const result = await verifyOpSignedIdToken(
			idToken,
			opJwks as { keys: import("@oidfed/core").JWK[] },
			OP_ID,
			RP1_ID,
		);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.sub).toBe("alice@example.com");
			expect(result.value.iss).toBe(OP_ID);
		}
	});

	it("rejects an id_token signed by a different key", async () => {
		const httpClient = localHttpClient(harness.port);
		const discovery = await discoverEntity(toEntityId(OP_ID), harness.bootstrap.trustAnchors, {
			httpClient,
		});
		const opJwks = discovery.trustChain.statements[0]?.payload.jwks as
			| { keys: Array<Record<string, unknown>> }
			| undefined;
		expect(opJwks).toBeDefined();

		// Sign with a freshly-generated key — NOT in the OP's jwks.
		const { privateKey } = await jose.generateKeyPair("ES256");
		const idToken = await new jose.SignJWT({ sub: "mallory", nonce: "n-test" })
			.setProtectedHeader({ alg: "ES256", kid: "attacker-kid" })
			.setIssuer(OP_ID)
			.setAudience(RP1_ID)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(privateKey);

		const result = await verifyOpSignedIdToken(
			idToken,
			opJwks as { keys: import("@oidfed/core").JWK[] },
			OP_ID,
			RP1_ID,
		);
		expect(result.ok).toBe(false);
	});

	it("rejects an id_token whose iss does not match the OP", async () => {
		const httpClient = localHttpClient(harness.port);
		const discovery = await discoverEntity(toEntityId(OP_ID), harness.bootstrap.trustAnchors, {
			httpClient,
		});
		const opJwks = discovery.trustChain.statements[0]?.payload.jwks as
			| { keys: Array<Record<string, unknown>> }
			| undefined;
		const opKeys = harness.bootstrap.entityKeys.get(OP_ID);
		const opPrivateJwk = opKeys?.signing as unknown as Record<string, unknown>;
		const opCryptoKey = await jose.importJWK(opPrivateJwk as jose.JWK, "ES256");

		// Token signed by the real OP key but with a wrong issuer claim — must still fail.
		const idToken = await new jose.SignJWT({ sub: "alice@example.com", nonce: "n-test" })
			.setProtectedHeader({ alg: "ES256", kid: opPrivateJwk.kid as string })
			.setIssuer("https://impostor.example.com")
			.setAudience(RP1_ID)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(opCryptoKey as Parameters<typeof jose.SignJWT.prototype.sign>[0]);

		const result = await verifyOpSignedIdToken(
			idToken,
			opJwks as { keys: import("@oidfed/core").JWK[] },
			OP_ID,
			RP1_ID,
		);
		expect(result.ok).toBe(false);
	});
});

describe("Request Object aud guard at OP /auth", () => {
	it("yields JSON 400 (no redirect to redirect_uri) when aud is not the OP", async () => {
		// Build a Request Object with aud pointing at a non-existent OP, signed by
		// RP1's actual key (so signature verification would succeed against the
		// federation-resolved RP jwks — meaning aud is the only thing blocking it).
		const opKeys = harness.bootstrap.entityKeys.get(RP1_ID);
		expect(opKeys).toBeDefined();
		const rpPrivateJwk = opKeys?.signing as unknown as Record<string, unknown>;

		const requestObjectJwt = await signEntityStatement(
			{
				iss: RP1_ID,
				client_id: RP1_ID,
				aud: "https://impostor.fed.oidfed.com",
				jti: crypto.randomUUID(),
				iat: Math.floor(Date.now() / 1000),
				exp: Math.floor(Date.now() / 1000) + 60,
				redirect_uri: `${RP1_ID}/callback`,
				response_type: "code",
				scope: "openid",
				state: "x",
				nonce: "n",
			},
			rpPrivateJwk as Parameters<typeof signEntityStatement>[1],
			{ kid: rpPrivateJwk.kid as string, typ: "oauth-authz-req+jwt" },
		);

		const jar = new CookieJar();
		const res = await send(
			jar,
			"GET",
			new URL(OP_ID).host,
			`/auth?request=${encodeURIComponent(requestObjectJwt)}&client_id=${encodeURIComponent(RP1_ID)}`,
		);
		expect(res.status).toBe(400);
		expect(res.headers["content-type"]).toMatch(/application\/json/);
		expect(res.headers.location).toBeUndefined();
		const body = JSON.parse(res.body) as Record<string, unknown>;
		expect(typeof body.error).toBe("string");
		expect(body.entity_id).toBe(OP_ID);
	});
});

describe("Explicit registration aud guard at OP /federation_registration", () => {
	it("rejects an Entity Configuration whose aud is not the OP's Entity Identifier", async () => {
		const rpKeys = harness.bootstrap.entityKeys.get(RP2_ID);
		expect(rpKeys).toBeDefined();
		const rpPrivateJwk = rpKeys?.signing as unknown as Record<string, unknown>;
		const rpPublicJwk = rpKeys?.public as unknown as Record<string, unknown>;

		const now = Math.floor(Date.now() / 1000);
		const ec = await signEntityStatement(
			{
				iss: RP2_ID,
				sub: RP2_ID,
				aud: "https://wrong-op.fed.oidfed.com",
				iat: now,
				exp: now + 600,
				jwks: { keys: [rpPublicJwk] },
				authority_hints: [TA_ID],
				metadata: {
					openid_relying_party: {
						redirect_uris: [`${RP2_ID}/callback`],
						client_registration_types: ["explicit"],
					},
				},
			},
			rpPrivateJwk as Parameters<typeof signEntityStatement>[1],
			{ kid: rpPrivateJwk.kid as string, typ: "entity-statement+jwt" },
		);

		const jar = new CookieJar();
		const res = await new Promise<RawResponse>((resolve, reject) => {
			const req = http.request(
				{
					method: "POST",
					host: "127.0.0.1",
					port: harness.port,
					path: "/federation_registration",
					headers: {
						Host: new URL(OP_ID).host,
						"Content-Type": "application/entity-statement+jwt",
						"Content-Length": String(Buffer.byteLength(ec)),
					},
				},
				(r) => {
					const chunks: Buffer[] = [];
					r.on("data", (c: Buffer) => chunks.push(c));
					r.on("end", () => {
						jar.ingest(new URL(OP_ID).host, r.headers["set-cookie"]);
						resolve({
							status: r.statusCode ?? 0,
							headers: r.headers,
							body: Buffer.concat(chunks).toString("utf8"),
						});
					});
					r.on("error", reject);
				},
			);
			req.on("error", reject);
			req.write(ec);
			req.end();
		});
		expect(res.status).toBe(400);
		// Authority returns application/json error envelope per its error-helper contract.
		expect(res.body).toMatch(/aud/i);
	});
});
