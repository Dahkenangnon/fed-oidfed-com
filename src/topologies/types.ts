// Mirror of https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/types.ts — keep in sync.
// Data-only shape; behavior lives in @oidfed/* packages.

export interface TopologyDefinition {
	name: string;
	description: string;
	entities: EntityDefinition[];
}

export interface EntityDefinition {
	id: string;
	role: "trust-anchor" | "intermediate" | "leaf";
	protocolRole?: "op" | "rp";
	authorityHints?: string[];
	metadata: Record<string, Record<string, unknown>>;
	metadataPolicy?: Record<string, Record<string, unknown>>;
	constraints?: { max_path_length?: number };
	trustMarkIssuers?: Record<string, string[]>;
	trustMarks?: Array<{ trust_mark_type: string; jwt: string }>;
	trustMarkOwners?: Record<string, { sub: string; jwks: { keys: unknown[] } }>;
	trustMarkDelegations?: Record<string, string>;
	entityConfigurationTtlSeconds?: number;
}
