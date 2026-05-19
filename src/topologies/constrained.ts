import type { TopologyDefinition } from "./types.js";

// Adapted from https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/constrained.ts — *.ofed.test → *.constr.fed.oidfed.com
// TA has max_path_length=0: only direct subordinates resolve; ia-deep + op-deep fail validation by design.

const TA = "https://ta.constr.fed.oidfed.com";
const OP_DIRECT = "https://op-direct.constr.fed.oidfed.com";
const IA_DEEP = "https://ia-deep.constr.fed.oidfed.com";
const OP_DEEP = "https://op-deep.constr.fed.oidfed.com";

export const constrainedTopology: TopologyDefinition = {
	name: "constrained",
	description:
		"TA with max_path_length=0 → direct OP + IA with nested OP (nested fails validation)",
	entities: [
		{
			id: TA,
			role: "trust-anchor",
			constraints: { max_path_length: 0 },
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA}/federation_fetch`,
					federation_list_endpoint: `${TA}/federation_list`,
					federation_resolve_endpoint: `${TA}/federation_resolve`,
					federation_historical_keys_endpoint: `${TA}/federation_historical_keys`,
				},
			},
		},
		{
			id: OP_DIRECT,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [TA],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP_DIRECT}/federation_registration`,
				},
				openid_provider: {
					issuer: OP_DIRECT,
					authorization_endpoint: `${OP_DIRECT}/auth`,
					token_endpoint: `${OP_DIRECT}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic"],
				},
			},
		},
		{
			id: IA_DEEP,
			role: "intermediate",
			authorityHints: [TA],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA_DEEP}/federation_fetch`,
					federation_list_endpoint: `${IA_DEEP}/federation_list`,
					federation_historical_keys_endpoint: `${IA_DEEP}/federation_historical_keys`,
				},
			},
		},
		{
			id: OP_DEEP,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA_DEEP],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP_DEEP}/federation_registration`,
				},
				openid_provider: {
					issuer: OP_DEEP,
					authorization_endpoint: `${OP_DEEP}/auth`,
					token_endpoint: `${OP_DEEP}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic"],
				},
			},
		},
	],
};
