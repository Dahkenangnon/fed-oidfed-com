import type { TopologyDefinition } from "./types.js";

// Adapted from https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/single-anchor.ts
// URL scheme: *.ofed.test → *.single.fed.oidfed.com; rp.ofed.test → rp1.single.fed.oidfed.com

const TA = "https://ta.single.fed.oidfed.com";
const OP = "https://op.single.fed.oidfed.com";
const RP1 = "https://rp1.single.fed.oidfed.com";
const RP2 = "https://rp2.single.fed.oidfed.com";

export const singleAnchorTopology: TopologyDefinition = {
	name: "single-anchor",
	description: "Minimal topology: 1 TA, 1 OP, 2 RPs (automatic + explicit registration)",
	entities: [
		{
			id: TA,
			role: "trust-anchor",
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${TA}/federation_fetch`,
					federation_list_endpoint: `${TA}/federation_list`,
					federation_extended_list_endpoint: `${TA}/federation_extended_list`,
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
			id: OP,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [TA],
			metadata: {
				federation_entity: {
					federation_registration_endpoint: `${OP}/federation_registration`,
				},
				openid_provider: {
					issuer: OP,
					authorization_endpoint: `${OP}/auth`,
					token_endpoint: `${OP}/token`,
					pushed_authorization_request_endpoint: `${OP}/request`,
					jwks_uri: `${OP}/jwks`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["ES256", "RS256"],
					client_registration_types_supported: ["automatic", "explicit"],
					token_endpoint_auth_methods_supported: ["private_key_jwt"],
					token_endpoint_auth_signing_alg_values_supported: ["ES256"],
					request_object_signing_alg_values_supported: ["ES256"],
					scopes_supported: ["openid", "profile", "email"],
					claims_supported: ["sub", "name", "preferred_username", "email", "email_verified"],
					grant_types_supported: ["authorization_code"],
				},
			},
		},
		{
			id: RP1,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [TA],
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
			authorityHints: [TA],
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
