# fed-oidfed-com

Reference implementation of OpenID Federation 1.0 — six federation topologies built on the [`@oidfed`](https://github.com/Dahkenangnon/oidfed) packages.

This repository doubles as the **canonical integrator sample**: a reader can study any `src/` file and learn the correct way to compose `@oidfed/core`, `@oidfed/authority`, `@oidfed/leaf`, and `@oidfed/oidc` into a real federation. Every entity factory mirrors a counterpart in the upstream e2e test bed at [`oidfed/tests/e2e/`](https://github.com/Dahkenangnon/oidfed/tree/main/tests/e2e); files that mirror an upstream participant or helper carry a `@see` JSDoc tag pointing to it.

## Topologies

| Topology | Description |
|---|---|
| `single-anchor` | 1 TA, 1 OP, 2 RPs (one configured for automatic registration, one for explicit) |
| `hierarchical` | TA → 2 Intermediates (edu, health) → leaf OP + RP each |
| `multi-anchor` | 2 TAs (gov, industry) → shared Intermediate → leaves |
| `cross-federation` | Two federations bridged by a dual-anchor entity |
| `constrained` | TA with `max_path_length=0` exercising chain rejection |
| `policy-operators` | IA exercising `subset_of` / `value` / `add` / `essential` |

## Try the live federation

The six topologies above are deployed live at `*.fed.oidfed.com`. Use [`explore.oidfed.com`](https://explore.oidfed.com) — a browser-based federation explorer — to inspect any of them: paste an entity URL (for example `https://single.fed.oidfed.com` or `https://ta.hier.fed.oidfed.com`) and the explorer renders the trust chain, entity statements, and resolved metadata inline.

## What this sample demonstrates

Every public symbol from `@oidfed/*` that an integrator commonly needs is exercised here:

| Symbol | Package |
|---|---|
| `entityId` (branded type factory) | `@oidfed/core` |
| `generateSigningKey` | `@oidfed/core` |
| `InMemoryJtiStore` | `@oidfed/core` |
| `TrustAnchorSet`, `HttpClient`, `EntityType`, `JWK` (types) | `@oidfed/core` |
| `createAuthorityServer` | `@oidfed/authority` |
| `AuthorityConfig`, `AuthorityServer`, `SubordinateRecord` (types) | `@oidfed/authority` |
| `MemoryKeyStore` | `@oidfed/authority` |
| `MemorySubordinateStore` | `@oidfed/authority` |
| `MemoryTrustMarkStore` | `@oidfed/authority` |
| `createLeafEntity`, `LeafEntity` | `@oidfed/leaf` |
| `discoverEntity` | `@oidfed/leaf` |
| `processAutomaticRegistration` | `@oidfed/oidc` |
| `automaticRegistration` (RP-side) | `@oidfed/oidc` |
| `explicitRegistration` (RP-side) | `@oidfed/oidc` |

## Architecture

- **One Node process, vhost-dispatched.** A single `http.Server` reads the `Host` header and routes to the right per-entity request listener.
- **Hono for authorities and federation-only leaves.** Pure federation logic, runtime-portable to workerd / Deno without code changes.
- **Express + `node-oidc-provider` for OPs.** `node-oidc-provider` is Node-only (it depends on `koa-compose` and Node streams). The federation endpoint subset is mounted alongside OIDC routes in the same Express app.
- **In-memory stores** (`MemoryKeyStore`, `MemorySubordinateStore`, `MemoryTrustMarkStore`) seeded at boot from each `TopologyDefinition`.
- **Key persistence.** Signing keys are minted on first boot and snapshotted to `~/.fed-oidfed/keys.json` (mode 0600) so process restarts don't invalidate previously-issued JWTs. Override the directory with `FED_OIDFED_KEYS_DIR=...`. Keys are demo and not HSM-backed.
- **Configurable outbound HTTP.** `BootstrapOptions.httpClient` lets a caller swap the OPs' outbound `fetch` for a custom client — used in the integration tests to keep the round-trip hermetic, and available in production to plug in fetch-policy enforcement (allowed-hosts, CIDR blocks, request throttling).

## Local development

### Prereqs

- Node.js 22+ (`engines.node = ">=22"`)
- pnpm 9+ (`pnpm-lock.yaml` is lockfileVersion 9.0)

### Install and verify

```bash
pnpm install
pnpm typecheck      # tsc --noEmit, strict
pnpm lint           # biome check src test
pnpm test           # vitest run, integration suite (17 cases, ~2.5s)
pnpm build          # tsc → dist/
```

### Dev server

```bash
pnpm dev            # tsx watch src/index.ts
# or run the built artifact:
pnpm build && pnpm start
```

Listens on `http://127.0.0.1:3000` by default. The vhost dispatcher reads the `Host` header directly — no reverse proxy needed for local development. Override the port via `PORT=3030 pnpm dev`.

### Curl playbook

```bash
# All 6 Trust Anchors (vhost dispatched by Host header)
for ta in ta.single ta.hier ta-gov.multi ta-x.xfed ta.constr ta.policy; do
  curl -sS -H "Host: ${ta}.fed.oidfed.com" \
       http://127.0.0.1:3000/.well-known/openid-federation | head -c 80; echo
done

# TA issues a subordinate statement for the OP
curl -sS -H "Host: ta.single.fed.oidfed.com" \
     "http://127.0.0.1:3000/federation_fetch?sub=https%3A%2F%2Fop.single.fed.oidfed.com" | head -c 80; echo

# OP OIDC discovery
curl -sS -H "Host: op.single.fed.oidfed.com" \
     http://127.0.0.1:3000/.well-known/openid-configuration | jq .issuer

# Decode an entity-statement JWT body
curl -sS -H "Host: ta.single.fed.oidfed.com" http://127.0.0.1:3000/.well-known/openid-federation \
  | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Browsers and Node's `fetch()` won't let you set the `Host` header (forbidden by spec). Use `curl -H` or a hosts file entry.

### Clean slate (regenerate keys)

```bash
rm -f ~/.fed-oidfed/keys.json
pnpm dev          # fresh ES256 keypair per entity, fresh snapshot
```

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Two `@oidfed/core` directories in `node_modules/.pnpm/` | The `pnpm.overrides` entry was removed. Restore it and reinstall. |
| Server boots but `curl` returns 404 with `No federation entity bound to host: <host>` | The `Host` header didn't reach the dispatcher. `fetch()` strips it; use `curl -H` or raw `http.request`. |
| `oidc-provider WARNING: a quick start development-only …` | Expected. `node-oidc-provider` warns about demo-mode config; noise, not a failure. |
| `EADDRINUSE :::3000` | `lsof -i :3000`, or `PORT=3030 pnpm dev`. |

## Endpoints exposed per entity role

| Role | Endpoints |
|---|---|
| Trust Anchor / Intermediate (Hono) | All paths dispatch through `authority.handler()` from `@oidfed/authority`: `/.well-known/openid-federation`, `/federation_fetch`, `/federation_list`, `/federation_extended_list`, `/federation_resolve`, `/federation_historical_keys`, `/federation_registration`, `/federation_trust_mark`, `/federation_trust_mark_status`, `/federation_trust_mark_list` |
| Leaf RP (Hono) | `/.well-known/openid-federation` |
| Leaf OP (Express + node-oidc-provider) | Federation: `/.well-known/openid-federation`, `/federation_fetch`, `/federation_list`, `/federation_resolve`, `/federation_registration`, `/federation_trust_mark`, `/federation_trust_mark_status`, `/federation_trust_mark_list`. OIDC: all routes mounted by `node-oidc-provider` (including `/auth`, `/token`, `/userinfo`, `/jwks`, `/.well-known/openid-configuration`). |

CORS is open (`Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, POST, OPTIONS`) on every federation endpoint so browser-based federation explorers can fetch trust chains cross-origin.

## License

[MIT](./LICENSE) — see `LICENSE`. Demo / reference implementation: signing keys are not HSM-backed and not suitable for production identity assertions.
