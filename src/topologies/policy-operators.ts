import type { TopologyDefinition } from "./types.js";

// Adapted from https://github.com/Dahkenangnon/oidfed/blob/main/tests/e2e/topologies/policy-operators.ts — *.ofed.test → *.policy.fed.oidfed.com
// IA policy operators exercised: subset_of, value, add, essential.

const TA = "https://ta.policy.fed.oidfed.com";
const IA = "https://ia.policy.fed.oidfed.com";
const OP = "https://op.policy.fed.oidfed.com";
const RP = "https://rp.policy.fed.oidfed.com";

export const policyOperatorsTopology: TopologyDefinition = {
	name: "policy-operators",
	description: "TA → IA with diverse policy operators (subset_of, value, add, essential) → OP + RP",
	entities: [
		{
			id: TA,
			role: "trust-anchor",
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
			id: IA,
			role: "intermediate",
			authorityHints: [TA],
			metadata: {
				federation_entity: {
					federation_fetch_endpoint: `${IA}/federation_fetch`,
					federation_list_endpoint: `${IA}/federation_list`,
					federation_historical_keys_endpoint: `${IA}/federation_historical_keys`,
				},
			},
			metadataPolicy: {
				openid_provider: {
					grant_types_supported: { subset_of: ["authorization_code"] },
					token_endpoint_auth_methods_supported: { value: ["private_key_jwt"] },
					id_token_signing_alg_values_supported: { add: ["ES256"] },
					subject_types_supported: { essential: true },
				},
			},
		},
		{
			id: OP,
			role: "leaf",
			protocolRole: "op",
			authorityHints: [IA],
			metadata: {
				openid_provider: {
					issuer: OP,
					authorization_endpoint: `${OP}/auth`,
					token_endpoint: `${OP}/token`,
					userinfo_endpoint: `${OP}/me`,
					pushed_authorization_request_endpoint: `${OP}/request`,
					federation_registration_endpoint: `${OP}/federation_registration`,
					jwks_uri: `${OP}/jwks`,
					response_types_supported: ["code"],
					// Intentionally single-alg here; the IA's metadata_policy `add` operator
					// extends this to include ES256 during chain resolution.
					id_token_signing_alg_values_supported: ["RS256"],
					grant_types_supported: ["authorization_code"],
					subject_types_supported: ["public"],
					// Intentionally weaker here; the IA's metadata_policy `value` operator
					// forces private_key_jwt during chain resolution.
					token_endpoint_auth_methods_supported: ["client_secret_basic"],
					token_endpoint_auth_signing_alg_values_supported: ["ES256", "RS256"],
					request_object_signing_alg_values_supported: ["ES256", "RS256"],
					client_registration_types_supported: ["automatic", "explicit"],
					scopes_supported: ["openid", "profile", "email"],
					claims_supported: ["sub", "name", "preferred_username", "email", "email_verified"],
				},
			},
		},
		{
			id: RP,
			role: "leaf",
			protocolRole: "rp",
			authorityHints: [IA],
			metadata: {
				openid_relying_party: {
					redirect_uris: [`${RP}/callback`],
					response_types: ["code"],
					grant_types: ["authorization_code"],
					client_registration_types: ["automatic"],
					token_endpoint_auth_method: "private_key_jwt",
				},
			},
		},
	],
};
