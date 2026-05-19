/**
 * End-to-end RP-side flows for the in-process federation:
 *
 *   - `discoverEntity` from `@oidfed/leaf` resolves an OP through the federation.
 *   - `automaticRegistration` from `@oidfed/oidc` builds a signed Request Object
 *     with embedded trust chain and an authorization URL pointing at the OP.
 *   - `explicitRegistration` from `@oidfed/oidc` POSTs a signed RP Entity
 *     Configuration to the OP's `federation_registration_endpoint` and
 *     consumes the resolved metadata response.
 *
 * These are the three marquee package functions an integrator builds an RP around.
 * Mirrors the patterns in `https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/scenarios/automatic-registration.test.ts`
 * and `https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/scenarios/explicit-registration.test.ts`
 * but exercises the actual fed-oidfed-com bootstrap with canonical entityIds
 * (no port rewriting). An in-process `HttpClient` rewrites outbound URLs to
 * `http://127.0.0.1:${port}` while preserving the original `Host` header so the
 * vhost dispatcher routes correctly.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import { decodeEntityStatement, entityId, isOk } from "@oidfed/core";
import { discoverEntity } from "@oidfed/leaf";
import { automaticRegistration, explicitRegistration } from "@oidfed/oidc";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type BootstrapResult, bootstrapFederation } from "../../src/bootstrap.js";
import type { EntityKeyPair } from "../../src/persistence.js";
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
	httpClient: ReturnType<typeof localHttpClient>;
}

let harness: Harness;

beforeAll(async () => {
	// Bind the listener first so we know the port; build the in-process HttpClient
	// against that port, then bootstrap with it so the OP's outbound federation
	// lookups (`processAutomaticRegistration`) also route through the in-process server.
	const server = http.createServer();
	const port = await new Promise<number>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			resolve((server.address() as AddressInfo).port);
		});
	});
	const httpClient = localHttpClient(port);

	// Use only single-anchor — it advertises both `automatic` and `explicit`
	// in `client_registration_types_supported`, and ships an RP for each.
	const bootstrap = await bootstrapFederation([singleAnchorTopology], { httpClient });

	server.on("request", (req, res) => {
		const listener = resolveListener(bootstrap.listeners, req.headers.host);
		if (!listener) {
			res.writeHead(404).end();
			return;
		}
		listener(req, res);
	});

	harness = { server, port, bootstrap, httpClient };
});

afterAll(async () => {
	await new Promise<void>((resolve, reject) => {
		harness.server.close((err) => (err ? reject(err) : resolve()));
	});
});

function keysOf(id: string): EntityKeyPair {
	const k = harness.bootstrap.entityKeys.get(id);
	if (!k) throw new Error(`No keys for ${id}`);
	return k;
}

describe("discoverEntity (leaf-side OP discovery)", () => {
	it("resolves the OP through the Trust Anchor and returns a branded DiscoveryResult", async () => {
		const { bootstrap, httpClient } = harness;
		const discovery = await discoverEntity(entityId(OP_ID), bootstrap.trustAnchors, { httpClient });

		expect(discovery.entityId).toBe(OP_ID);
		expect(discovery.trustChain.trustAnchorId).toBe(TA_ID);
		expect(discovery.trustChain.statements.length).toBeGreaterThanOrEqual(2);
		expect(discovery.resolvedMetadata.openid_provider).toBeDefined();

		const opMeta = discovery.resolvedMetadata.openid_provider as Record<string, unknown>;
		expect(opMeta.issuer).toBe(OP_ID);
		expect(opMeta.client_registration_types_supported).toEqual(["automatic", "explicit"]);
	});
});

describe("automaticRegistration (RP1 → OP)", () => {
	it("builds a valid Request Object JWT with trust_chain header and an authorization URL", async () => {
		const { bootstrap, httpClient } = harness;
		const rp1Keys = keysOf(RP1_ID);

		const discovery = await discoverEntity(entityId(OP_ID), bootstrap.trustAnchors, { httpClient });

		const result = await automaticRegistration(
			discovery,
			{
				entityId: entityId(RP1_ID),
				signingKeys: [rp1Keys.signing as Record<string, unknown>],
				authorityHints: [entityId(TA_ID)],
				metadata: {
					openid_relying_party: {
						redirect_uris: [`${RP1_ID}/callback`],
						response_types: ["code"],
						grant_types: ["authorization_code"],
						client_registration_types: ["automatic"],
						token_endpoint_auth_method: "private_key_jwt",
					},
				},
				requestDelivery: "query",
			},
			{
				client_id: RP1_ID,
				redirect_uri: `${RP1_ID}/callback`,
				response_type: "code",
				scope: "openid",
			},
			bootstrap.trustAnchors,
			{ httpClient },
		);

		expect(result.requestObjectJwt).toBeTruthy();
		expect(result.delivery).toBe("query");
		if (result.delivery !== "query") return;
		expect(result.authorizationUrl).toContain(`${OP_ID}/auth`);
		expect(result.trustChain.trustAnchorId).toBe(TA_ID);
		expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));

		const decoded = decodeEntityStatement(result.requestObjectJwt);
		expect(isOk(decoded)).toBe(true);
		if (isOk(decoded)) {
			const header = decoded.value.header as Record<string, unknown>;
			const payload = decoded.value.payload as Record<string, unknown>;

			expect(header.typ).toBe("oauth-authz-req+jwt");
			expect(Array.isArray(header.trust_chain)).toBe(true);
			expect(payload.iss).toBe(RP1_ID);
			expect(payload.client_id).toBe(RP1_ID);
			expect(payload.aud).toBe(OP_ID);
			expect(payload.jti).toBeTruthy();
			expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
			expect(payload.scope).toBe("openid");
		}
	});

	it("the OP does not 5xx when the Request Object is presented at /auth", async () => {
		const { bootstrap, httpClient } = harness;
		const rp1Keys = keysOf(RP1_ID);

		const discovery = await discoverEntity(entityId(OP_ID), bootstrap.trustAnchors, { httpClient });

		const result = await automaticRegistration(
			discovery,
			{
				entityId: entityId(RP1_ID),
				signingKeys: [rp1Keys.signing as Record<string, unknown>],
				authorityHints: [entityId(TA_ID)],
				metadata: {
					openid_relying_party: {
						redirect_uris: [`${RP1_ID}/callback`],
						response_types: ["code"],
						grant_types: ["authorization_code"],
						client_registration_types: ["automatic"],
						token_endpoint_auth_method: "private_key_jwt",
					},
				},
				requestDelivery: "query",
			},
			{
				client_id: RP1_ID,
				redirect_uri: `${RP1_ID}/callback`,
				response_type: "code",
				scope: "openid",
			},
			bootstrap.trustAnchors,
			{ httpClient },
		);

		expect(result.delivery).toBe("query");
		if (result.delivery !== "query") return;
		const response = await httpClient(result.authorizationUrl);
		// Federation validation must succeed (no 400 from processAutomaticRegistration);
		// downstream node-oidc-provider may still return 4xx because dynamic-client
		// wiring is out of scope here, but it MUST NOT 5xx.
		expect(response.status).toBeLessThan(500);
	});
});

describe("explicitRegistration (RP2 → OP)", () => {
	it("POSTs a signed Entity Configuration and receives a resolved-metadata response", async () => {
		const { bootstrap, httpClient } = harness;
		const rp2Keys = keysOf(RP2_ID);

		const discovery = await discoverEntity(entityId(OP_ID), bootstrap.trustAnchors, { httpClient });

		const result = await explicitRegistration(
			discovery,
			{
				entityId: entityId(RP2_ID),
				signingKeys: [rp2Keys.signing as Record<string, unknown>],
				authorityHints: [entityId(TA_ID)],
				metadata: {
					openid_relying_party: {
						redirect_uris: [`${RP2_ID}/callback`],
						response_types: ["code"],
						grant_types: ["authorization_code"],
						client_registration_types: ["explicit"],
						token_endpoint_auth_method: "private_key_jwt",
					},
				},
			},
			bootstrap.trustAnchors,
			{ httpClient },
		);

		expect(result.clientId).toBe(RP2_ID);
		expect(result.registeredMetadata).toBeDefined();
		const redirects = result.registeredMetadata.redirect_uris as readonly string[] | undefined;
		expect(redirects).toContain(`${RP2_ID}/callback`);
		expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		expect(result.trustChainExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
		expect(result.registrationStatement.payload.iss).toBe(OP_ID);
		expect(result.registrationStatement.payload.sub).toBe(RP2_ID);
		expect(result.registrationStatement.payload.aud).toBe(RP2_ID);

		const trustAnchorClaim = result.registrationStatement.payload.trust_anchor as
			| string
			| undefined;
		expect(trustAnchorClaim).toBe(TA_ID);

		const authorityHints = result.registrationStatement.payload.authority_hints as
			| readonly string[]
			| undefined;
		expect(authorityHints).toEqual([TA_ID]);
	});
});
