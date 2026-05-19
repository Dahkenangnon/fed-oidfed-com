import type { TopologyDefinition } from "./types.js";

// Adapted from https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/multi-anchor.ts — *.ofed.test → *.multi.fed.oidfed.com
// ia-shared.ofed.test → ia.multi.fed.oidfed.com (shorter subdomain)

const TA_GOV = "https://ta-gov.multi.fed.oidfed.com";
const TA_IND = "https://ta-industry.multi.fed.oidfed.com";
const IA = "https://ia.multi.fed.oidfed.com";
const OP = "https://op.multi.fed.oidfed.com";
const RP1 = "https://rp1.multi.fed.oidfed.com";
const RP2 = "https://rp2.multi.fed.oidfed.com";

export const multiAnchorTopology: TopologyDefinition = {
	name: "multi-anchor",
	description: "2 TAs (gov, industry) → shared IA → OP + 2 RPs",
	entities: [
		{
			id: TA_GOV,
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA_GOV}/federation_fetch`,
					federation_list_endpoint: `${TA_GOV}/federation_list`,
					federation_resolve_endpoint: `${TA_GOV}/federation_resolve`,
					federation_historical_keys_endpoint: `${TA_GOV}/federation_historical_keys`,
				},
			},
		},
		{
			id: TA_IND,
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA_IND}/federation_fetch`,
					federation_list_endpoint: `${TA_IND}/federation_list`,
					federation_resolve_endpoint: `${TA_IND}/federation_resolve`,
					federation_historical_keys_endpoint: `${TA_IND}/federation_historical_keys`,
				},
			},
		},
		{
			id: IA,
			role: "intermediate",
			authorityHints: [TA_GOV, TA_IND],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA}/federation_fetch`,
					federation_list_endpoint: `${IA}/federation_list`,
					federation_resolve_endpoint: `${IA}/federation_resolve`,
					federation_historical_keys_endpoint: `${IA}/federation_historical_keys`,
				},
			},
		},
		{
			id: OP,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP}/federation_registration`,
				},
				openid_provider: {
					issuer: OP,
					authorization_endpoint: `${OP}/auth`,
					token_endpoint: `${OP}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: RP1,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA],
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
			id: RP2,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA],
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
