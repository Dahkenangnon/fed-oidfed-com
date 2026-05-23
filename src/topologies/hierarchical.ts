import type { TopologyDefinition } from "./types.js";

// Adapted from https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/hierarchical.ts — *.ofed.test → *.hier.fed.oidfed.com

const TA = "https://ta.hier.fed.oidfed.com";
const IA_EDU = "https://ia-edu.hier.fed.oidfed.com";
const IA_HEALTH = "https://ia-health.hier.fed.oidfed.com";
const OP_UNI = "https://op-uni.hier.fed.oidfed.com";
const OP_HOSPITAL = "https://op-hospital.hier.fed.oidfed.com";
const RP1 = "https://rp1.hier.fed.oidfed.com";
const RP2 = "https://rp2.hier.fed.oidfed.com";

export const hierarchicalTopology: TopologyDefinition = {
	name: "hierarchical",
	description: "TA → 2 Intermediates (edu, health), each with OP + RP",
	entities: [
		{
			id: TA,
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA}/federation_fetch`,
					federation_list_endpoint: `${TA}/federation_list`,
					federation_resolve_endpoint: `${TA}/federation_resolve`,
					federation_trust_mark_endpoint: `${TA}/federation_trust_mark`,
					federation_trust_mark_status_endpoint: `${TA}/federation_trust_mark_status`,
					federation_trust_mark_list_endpoint: `${TA}/federation_trust_mark_list`,
					federation_historical_keys_endpoint: `${TA}/federation_historical_keys`,
				},
			},
			trustMarkIssuers: {
				[`${TA}/trust-marks/certified`]: [TA],
			},
		},
		{
			id: IA_EDU,
			role: "intermediate",
			authorityHints: [TA],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA_EDU}/federation_fetch`,
					federation_list_endpoint: `${IA_EDU}/federation_list`,
					federation_resolve_endpoint: `${IA_EDU}/federation_resolve`,
					federation_historical_keys_endpoint: `${IA_EDU}/federation_historical_keys`,
				},
			},
			metadataPolicy: {
				openid_provider: {
					token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
				},
			},
		},
		{
			id: IA_HEALTH,
			role: "intermediate",
			authorityHints: [TA],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA_HEALTH}/federation_fetch`,
					federation_list_endpoint: `${IA_HEALTH}/federation_list`,
					federation_resolve_endpoint: `${IA_HEALTH}/federation_resolve`,
					federation_historical_keys_endpoint: `${IA_HEALTH}/federation_historical_keys`,
				},
			},
			metadataPolicy: {
				openid_provider: {
					token_endpoint_auth_methods_supported: { default: ["private_key_jwt"] },
				},
			},
		},
		{
			id: OP_UNI,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA_EDU],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP_UNI}/federation_registration`,
				},
				openid_provider: {
					issuer: OP_UNI,
					authorization_endpoint: `${OP_UNI}/auth`,
					token_endpoint: `${OP_UNI}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256", "RS256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: RP1,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA_EDU],
			metadata: {
				openid_relying_party: {
					redirect_uris: [`${RP1}/callback`],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
		{
			id: OP_HOSPITAL,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA_HEALTH],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP_HOSPITAL}/federation_registration`,
				},
				openid_provider: {
					issuer: OP_HOSPITAL,
					authorization_endpoint: `${OP_HOSPITAL}/auth`,
					token_endpoint: `${OP_HOSPITAL}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256", "RS256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: RP2,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA_HEALTH],
			metadata: {
				openid_relying_party: {
					redirect_uris: [`${RP2}/callback`],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["explicit"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
	],
};
