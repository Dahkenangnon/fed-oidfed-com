/**
 * Federation bootstrap — turns the declarative `TopologyDefinition[]` in
 * `src/topologies/` into running entity instances (authorities + leaves) and
 * a `Host`-header-indexed listener registry consumed by `src/server.ts`.
 *
 * Mirrors `https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/helpers/launcher.ts` in shape and ordering, so a
 * reader can map fed-oidfed-com directly onto the canonical e2e launcher.
 * Six-phase build:
 *   1. Load or generate signing keys, persist snapshot
 *   2. Per topology, derive its TrustAnchorSet from the TA entities
 *   3. Create authority-role entities (TA + Intermediate) and bind them to vhosts
 *   4. Create leaf-role entities (RPs and leaf-role OPs) and bind them to vhosts
 *   5. Register subordinates in each parent's MemorySubordinateStore
 *   6. Register topology aliases (e.g. `single.fed.oidfed.com` → TA)
 *
 * @see https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/helpers/launcher.ts
 */

import type { RequestListener } from "node:http";
import { getRequestListener } from "@hono/node-server";
import type { AuthorityConfig, AuthorityServer, SubordinateRecord } from "@oidfed/authority";
import {
	MemoryKeyStore,
	MemorySubordinateStore,
	MemoryTrustMarkStore,
	createAuthorityServer,
	sanitizeSubordinateMetadata,
} from "@oidfed/authority";
import type { EntityType, HttpClient, JWK, TrustAnchorSet } from "@oidfed/core";
import { entityId, generateSigningKey } from "@oidfed/core";
import { type LeafEntity, createLeafEntity } from "@oidfed/leaf";
import { createAuthorityHonoApp } from "./entities/authority.js";
import { createDemoRpHonoApp } from "./entities/demo-rp.js";
import { createLeafHonoApp } from "./entities/leaf.js";
import { createOpExpressApp } from "./entities/op.js";

/**
 * RPs that participate in the visible OIDC demo flow. Single-anchor demonstrates
 * both registration modes (RP1 automatic, RP2 explicit); every other topology
 * picks one automatic-registration RP so the dance can be exercised end-to-end.
 * The constrained topology has no demo RP — that topology exists to exercise
 * the max_path_length chain-validation failure, not the OIDC flow.
 * Other RPs serve only their federation surface (`/.well-known/openid-federation`).
 */
const DEMO_RP_ENTITY_IDS: ReadonlySet<string> = new Set([
	"https://rp1.single.fed.oidfed.com",
	"https://rp2.single.fed.oidfed.com",
	"https://rp1.hier.fed.oidfed.com",
	"https://rp1.multi.fed.oidfed.com",
	"https://rp-x.xfed.fed.oidfed.com",
	"https://rp.policy.fed.oidfed.com",
]);
import { entityIdToHostname, topologyAliases } from "./lib/subdomain.js";
import {
	type EntityKeyPair,
	buildSnapshot,
	loadKeySnapshot,
	saveKeySnapshot,
} from "./persistence.js";
import type { EntityDefinition, TopologyDefinition } from "./topologies/types.js";

export interface BootstrapResult {
	listeners: Map<string, RequestListener>;
	trustAnchors: TrustAnchorSet;
	entityCount: number;
	/**
	 * Public + private signing keys for every bootstrapped entity, indexed by
	 * entityId. Integration tests use this to drive RP-side flows
	 * (`automaticRegistration`, `explicitRegistration`) against the in-process OP.
	 */
	entityKeys: ReadonlyMap<string, EntityKeyPair>;
}

interface EntityRuntime {
	server: AuthorityServer | LeafEntity;
	keys: EntityKeyPair;
}

export interface BootstrapOptions {
	/**
	 * Outbound HTTP client for OPs' federation lookups. Defaults to the global
	 * `fetch`. Override for hermetic integration tests, fetch-policy enforcement,
	 * or request-throttling proxies.
	 */
	httpClient?: HttpClient;
}

export async function bootstrapFederation(
	topologies: readonly TopologyDefinition[],
	options: BootstrapOptions = {},
): Promise<BootstrapResult> {
	// 1. Load or generate keys (persisted across process restarts).
	const snapshot = await loadKeySnapshot();
	const allKeys = new Map<string, EntityKeyPair>(snapshot ? Object.entries(snapshot.entities) : []);
	let mintedNew = false;

	const allEntities: EntityDefinition[] = topologies.flatMap((t) => t.entities);
	for (const e of allEntities) {
		const existing = allKeys.get(e.id);
		if (!existing) {
			const key = await generateSigningKey("ES256");
			const entry: EntityKeyPair = {
				signing: key.privateKey as JWK,
				public: key.publicKey as JWK,
			};
			// OPs additionally need an RSA/RS256 key for OIDC Core ID-token signing.
			if (e.protocolRole === "op") {
				const rs = await generateSigningKey("RS256");
				entry.oidcSigning = rs.privateKey as JWK;
				entry.oidcPublic = rs.publicKey as JWK;
			}
			allKeys.set(e.id, entry);
			mintedNew = true;
		} else if (e.protocolRole === "op" && !existing.oidcSigning) {
			// Snapshot predates RS256 support — backfill an OIDC RSA key without
			// rotating the entity's federation signing key.
			const rs = await generateSigningKey("RS256");
			allKeys.set(e.id, {
				...existing,
				oidcSigning: rs.privateKey as JWK,
				oidcPublic: rs.publicKey as JWK,
			});
			mintedNew = true;
		}
	}
	if (mintedNew) {
		await saveKeySnapshot(buildSnapshot(allKeys));
	}

	const getKeys = (id: string): EntityKeyPair => {
		const k = allKeys.get(id);
		if (!k) throw new Error(`No keys for entity ${id}`);
		return k;
	};

	const listeners = new Map<string, RequestListener>();
	const runtimes = new Map<string, EntityRuntime>();
	const subordinateStores = new Map<string, MemorySubordinateStore>();

	// 2. Per-topology pass: build the trust anchor set for THIS federation, then create entities.
	//    Each topology has its own trust anchor set; cross-topology trust does not flow.
	for (const topology of topologies) {
		const taEntities = topology.entities.filter((e) => e.role === "trust-anchor");
		const topologyTrustAnchors: TrustAnchorSet = new Map(
			taEntities.map((ta) => [entityId(ta.id), { jwks: { keys: [getKeys(ta.id).public] } }]),
		);

		// 3. Create authority entities (TA + Intermediate) for this topology.
		//    OPs configured with role: "leaf" are built in step 4 alongside RPs;
		//    a topology that places an OP in the intermediate or trust-anchor role
		//    would land here and need its own authority + oidc composition path.
		for (const entity of topology.entities) {
			const isAuthority = entity.role === "trust-anchor" || entity.role === "intermediate";
			if (!isAuthority) continue;

			const keys = getKeys(entity.id);
			const subordinateStore = new MemorySubordinateStore();
			subordinateStores.set(entity.id, subordinateStore);

			const authorityHints = entity.authorityHints?.map((h) => entityId(h));
			const trustMarkStore = new MemoryTrustMarkStore();
			const keyStore = new MemoryKeyStore(keys.signing);

			const authorityConfig: Record<string, unknown> = {
				entityId: entityId(entity.id),
				signingKeys: [keys.signing],
				metadata: {
					federation_entity: (entity.metadata.federation_entity as Record<string, string>) ?? {},
					...Object.fromEntries(
						Object.entries(entity.metadata).filter(([k]) => k !== "federation_entity"),
					),
				},
				subordinateStore,
				keyStore,
				trustMarkStore,
				trustAnchors: topologyTrustAnchors,
			};
			if (authorityHints) authorityConfig.authorityHints = authorityHints;
			if (entity.trustMarkIssuers) authorityConfig.trustMarkIssuers = entity.trustMarkIssuers;
			if (entity.trustMarks) authorityConfig.trustMarks = entity.trustMarks;
			if (entity.trustMarkOwners) authorityConfig.trustMarkOwners = entity.trustMarkOwners;
			if (entity.trustMarkDelegations) {
				authorityConfig.trustMarkDelegations = entity.trustMarkDelegations;
			}
			if (entity.entityConfigurationTtlSeconds !== undefined) {
				authorityConfig.entityConfigurationTtlSeconds = entity.entityConfigurationTtlSeconds;
			}

			// The dynamically-assembled `Record<string, unknown>` above is structurally
			// compatible with AuthorityConfig; the cast bridges from the lambda-built
			// object to the package's nominal type.
			const authority = createAuthorityServer(authorityConfig as unknown as AuthorityConfig);
			runtimes.set(entity.id, { server: authority, keys });

			const hostname = entityIdToHostname(entity.id);
			const honoApp = createAuthorityHonoApp(authority, entity.id);
			listeners.set(hostname, getRequestListener(honoApp.fetch));
		}

		// 4. Create leaf entities for this topology — RPs and leaf-role OPs.
		for (const entity of topology.entities) {
			if (entity.role !== "leaf") continue;

			const keys = getKeys(entity.id);
			const authorityHints = entity.authorityHints?.map((h) => entityId(h)) ?? [];

			// Republish the openid_relying_party metadata with an explicit jwks field so that
			// signature verification finds the key on both the openid_relying_party metadata
			// JWKS path and the federation EC top-level jwks. Clone — do not mutate the
			// topology data.
			const baseRpMeta = entity.metadata.openid_relying_party as
				| Record<string, unknown>
				| undefined;
			const enrichedMetadata = baseRpMeta
				? {
						...entity.metadata,
						openid_relying_party: {
							...baseRpMeta,
							jwks: { keys: [keys.public] },
						},
					}
				: entity.metadata;

			const leafConfig: Record<string, unknown> = {
				entityId: entityId(entity.id),
				signingKeys: [keys.signing],
				authorityHints,
				metadata: enrichedMetadata,
			};
			if (entity.trustMarks) leafConfig.trustMarks = entity.trustMarks;
			if (entity.entityConfigurationTtlSeconds !== undefined) {
				leafConfig.entityConfigurationTtlSeconds = entity.entityConfigurationTtlSeconds;
			}

			// Same structurally-compatible-but-nominally-distinct seam used in the
			// upstream e2e launcher at https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/helpers/launcher.ts#L188.
			const leaf = createLeafEntity(
				leafConfig as unknown as Parameters<typeof createLeafEntity>[0],
			);
			runtimes.set(entity.id, { server: leaf, keys });

			const hostname = entityIdToHostname(entity.id);

			if (entity.protocolRole === "op") {
				const expressApp = createOpExpressApp({
					leaf,
					entityId: entity.id,
					trustAnchors: topologyTrustAnchors,
					signingKey: keys.signing,
					publicSigningKey: keys.public,
					...(keys.oidcSigning !== undefined && keys.oidcPublic !== undefined
						? { oidcSigningKey: keys.oidcSigning, oidcPublicSigningKey: keys.oidcPublic }
						: {}),
					...(options.httpClient !== undefined ? { httpClient: options.httpClient } : {}),
				});
				listeners.set(hostname, expressApp as unknown as RequestListener);
			} else if (entity.protocolRole === "rp" && DEMO_RP_ENTITY_IDS.has(entity.id)) {
				// Demo RPs participate in the visible OIDC flow.
				const opEntity = topology.entities.find((e) => e.protocolRole === "op");
				if (!opEntity) {
					throw new Error(`Demo RP ${entity.id} has no OP in its topology`);
				}
				const rpMeta = (enrichedMetadata.openid_relying_party as Record<string, unknown>) ?? {};
				const registrationTypes = rpMeta.client_registration_types as string[] | undefined;
				const registrationMode = registrationTypes?.[0] === "explicit" ? "explicit" : "automatic";
				const demoApp = createDemoRpHonoApp({
					leaf,
					entityId: entity.id,
					opEntityId: opEntity.id,
					signingKey: keys.signing,
					publicSigningKey: keys.public,
					trustAnchors: topologyTrustAnchors,
					metadata: enrichedMetadata as Record<string, Record<string, unknown>>,
					registrationMode,
					authorityHints: entity.authorityHints ?? [],
					...(entity.protocolDelivery !== undefined
						? { requestDelivery: entity.protocolDelivery }
						: {}),
					...(options.httpClient !== undefined ? { httpClient: options.httpClient } : {}),
				});
				listeners.set(hostname, getRequestListener(demoApp.fetch));
			} else {
				// Non-demo RPs serve only the federation surface via the bare leaf factory.
				const honoApp = createLeafHonoApp(leaf, entity.id);
				listeners.set(hostname, getRequestListener(honoApp.fetch));
			}
		}

		// 5. Register each entity in its parent's subordinate store.
		for (const entity of topology.entities) {
			if (!entity.authorityHints) continue;

			for (const parentId of entity.authorityHints) {
				const store = subordinateStores.get(parentId);
				if (!store) continue;

				const keys = getKeys(entity.id);
				const parentEntity = topology.entities.find((e) => e.id === parentId);
				const parentConstraints = parentEntity?.constraints;

				// Strip the subordinate's own operational federation_entity claims —
				// those belong only in the subordinate's Entity Configuration, not in
				// the parent's Subordinate Statement.
				const subordinateMetadata = sanitizeSubordinateMetadata(
					entity.metadata as Record<string, unknown>,
				);

				const record: SubordinateRecord = {
					entityId: entityId(entity.id),
					jwks: { keys: [keys.public] },
					...(subordinateMetadata !== undefined ? { metadata: subordinateMetadata } : {}),
					...(entity.metadataPolicy !== undefined ? { metadataPolicy: entity.metadataPolicy } : {}),
					...(parentConstraints !== undefined ? { constraints: parentConstraints } : {}),
					entityTypes: getEntityTypes(entity) as EntityType[],
					isIntermediate: entity.role === "intermediate",
					createdAt: Date.now() / 1000,
					updatedAt: Date.now() / 1000,
				};

				await store.add(record);
			}
		}
	}

	// 6. Register topology aliases (e.g., single.fed.oidfed.com → ta.single.fed.oidfed.com).
	for (const alias of topologyAliases()) {
		const target = listeners.get(alias.canonical);
		if (!target) continue;
		for (const aliasHost of alias.aliases) {
			listeners.set(aliasHost, target);
		}
	}

	// Aggregate TrustAnchorSet spanning all topologies — handy for callers that
	// want every TA at once (the in-process integration tests). TrustAnchorSet is
	// `ReadonlyMap<EntityId, ...>`; populate via a mutable Map then bridge.
	const trustAnchorsMut = new Map<ReturnType<typeof entityId>, { jwks: { keys: JWK[] } }>();
	for (const topology of topologies) {
		for (const e of topology.entities) {
			if (e.role === "trust-anchor") {
				trustAnchorsMut.set(entityId(e.id), { jwks: { keys: [getKeys(e.id).public] } });
			}
		}
	}
	const trustAnchors = trustAnchorsMut as unknown as TrustAnchorSet;

	return {
		listeners,
		trustAnchors,
		entityCount: allEntities.length,
		entityKeys: allKeys,
	};
}

function getEntityTypes(entity: EntityDefinition): string[] {
	return Object.keys(entity.metadata).length > 0
		? Object.keys(entity.metadata)
		: ["federation_entity"];
}
