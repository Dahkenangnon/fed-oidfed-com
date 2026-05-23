import type { TopologyDefinition } from "./types.js";

// Adapted from https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/cross-federation.ts — *.ofed.test → *.xfed.fed.oidfed.com

const TA_X = "https://ta-x.xfed.fed.oidfed.com";
const IA_X = "https://ia-x.xfed.fed.oidfed.com";
const OP_X = "https://op-x.xfed.fed.oidfed.com";
const RP_X = "https://rp-x.xfed.fed.oidfed.com";
const TA_Y = "https://ta-y.xfed.fed.oidfed.com";
const IA_Y = "https://ia-y.xfed.fed.oidfed.com";
const OP_Y = "https://op-y.xfed.fed.oidfed.com";
const RP_Y = "https://rp-y.xfed.fed.oidfed.com";
const BRIDGE = "https://bridge.xfed.fed.oidfed.com";

export const crossFederationTopology: TopologyDefinition = {
	name: "cross-federation",
	description: "2 federations (X, Y) linked by a bridge entity subordinate to both TAs",
	entities: [
		// Federation X
		{
			id: TA_X,
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA_X}/federation_fetch`,
					federation_list_endpoint: `${TA_X}/federation_list`,
					federation_resolve_endpoint: `${TA_X}/federation_resolve`,
					federation_historical_keys_endpoint: `${TA_X}/federation_historical_keys`,
				},
			},
		},
		{
			id: IA_X,
			role: "intermediate",
			authorityHints: [TA_X],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA_X}/federation_fetch`,
					federation_list_endpoint: `${IA_X}/federation_list`,
					federation_resolve_endpoint: `${IA_X}/federation_resolve`,
					federation_historical_keys_endpoint: `${IA_X}/federation_historical_keys`,
				},
			},
		},
		{
			id: OP_X,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA_X],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP_X}/federation_registration`,
				},
				openid_provider: {
					issuer: OP_X,
					authorization_endpoint: `${OP_X}/auth`,
					token_endpoint: `${OP_X}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256", "RS256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: RP_X,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA_X],
			metadata: {
				openid_relying_party: {
					redirect_uris: [`${RP_X}/callback`],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
		// Federation Y
		{
			id: TA_Y,
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA_Y}/federation_fetch`,
					federation_list_endpoint: `${TA_Y}/federation_list`,
					federation_resolve_endpoint: `${TA_Y}/federation_resolve`,
					federation_historical_keys_endpoint: `${TA_Y}/federation_historical_keys`,
				},
			},
		},
		{
			id: IA_Y,
			role: "intermediate",
			authorityHints: [TA_Y],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA_Y}/federation_fetch`,
					federation_list_endpoint: `${IA_Y}/federation_list`,
					federation_resolve_endpoint: `${IA_Y}/federation_resolve`,
					federation_historical_keys_endpoint: `${IA_Y}/federation_historical_keys`,
				},
			},
		},
		{
			id: OP_Y,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA_Y],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP_Y}/federation_registration`,
				},
				openid_provider: {
					issuer: OP_Y,
					authorization_endpoint: `${OP_Y}/auth`,
					token_endpoint: `${OP_Y}/token`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256", "RS256"],
					client_registration_types_supported: ["automatic", "explicit"],
				},
			},
		},
		{
			id: RP_Y,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA_Y],
			metadata: {
				openid_relying_party: {
					redirect_uris: [`${RP_Y}/callback`],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
		// Bridge: subordinate of both TA_X and TA_Y
		{
			id: BRIDGE,
			role: "intermediate",
			authorityHints: [TA_X, TA_Y],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${BRIDGE}/federation_fetch`,
					federation_list_endpoint: `${BRIDGE}/federation_list`,
					federation_resolve_endpoint: `${BRIDGE}/federation_resolve`,
					federation_historical_keys_endpoint: `${BRIDGE}/federation_historical_keys`,
				},
			},
		},
	],
};
