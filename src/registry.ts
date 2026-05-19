/**
 * Read-only hostname → request-listener lookup. Hostnames are normalised
 * (lower-cased, port stripped) before lookup so `Host: TA.single.fed.oidfed.com:443`
 * and `ta.single.fed.oidfed.com` resolve to the same entity.
 */

import type { RequestListener } from "node:http";

export type ListenerRegistry = ReadonlyMap<string, RequestListener>;

export function resolveListener(
	registry: ListenerRegistry,
	hostHeader: string | undefined,
): RequestListener | null {
	if (!hostHeader) return null;
	const host = hostHeader.replace(/:\d+$/, "").toLowerCase();
	return registry.get(host) ?? null;
}
