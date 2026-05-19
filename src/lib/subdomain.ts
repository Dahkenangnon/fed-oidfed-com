/**
 * Subdomain helpers — bidirectional conversion between an entity's canonical
 * `entityId` URL and its hostname, plus the alias table used to register
 * extra hostnames (e.g. `single.fed.oidfed.com` is an alias for `ta.single.fed.oidfed.com`).
 */

export type TopologyShortName = "single" | "hier" | "multi" | "xfed" | "constr" | "policy";

export interface SubdomainAlias {
	readonly canonical: string;
	readonly aliases: readonly string[];
}

const ROOT_DOMAIN = "fed.oidfed.com";

export function entityIdToHostname(entityId: string): string {
	const url = new URL(entityId);
	return url.hostname;
}

export function buildEntityId(shortName: string, topology: TopologyShortName): string {
	return `https://${shortName}.${topology}.${ROOT_DOMAIN}`;
}

export function topologyAliases(): readonly SubdomainAlias[] {
	return [
		{
			canonical: `ta.single.${ROOT_DOMAIN}`,
			aliases: [`single.${ROOT_DOMAIN}`, `minimal.${ROOT_DOMAIN}`],
		},
	];
}
