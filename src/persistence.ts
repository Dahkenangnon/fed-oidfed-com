/**
 * Signing-key snapshot — fed-oidfed-com-specific addition on top of the
 * e2e launcher (which mints fresh keys every run). Persisting keys to
 * `~/.fed-oidfed/keys.json` keeps entity statement signatures stable
 * across process restarts so downstream trust chains stay valid.
 *
 * Override the directory with `FED_OIDFED_KEYS_DIR=/some/path`. The snapshot
 * file is written with mode 0600.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { JWK } from "@oidfed/core";

export interface EntityKeyPair {
	signing: JWK;
	public: JWK;
}

export interface KeySnapshot {
	version: 1;
	createdAt: string;
	entities: Record<string, EntityKeyPair>;
}

const DEFAULT_DIR = process.env.FED_OIDFED_KEYS_DIR ?? join(homedir(), ".fed-oidfed");
const SNAPSHOT_FILE = "keys.json";

export function resolveSnapshotPath(dir: string = DEFAULT_DIR): string {
	return join(dir, SNAPSHOT_FILE);
}

export async function loadKeySnapshot(
	path: string = resolveSnapshotPath(),
): Promise<KeySnapshot | null> {
	try {
		const buf = await readFile(path, "utf8");
		const parsed = JSON.parse(buf) as KeySnapshot;
		if (parsed.version !== 1 || typeof parsed.entities !== "object") {
			throw new Error(`Invalid snapshot version or shape at ${path}`);
		}
		return parsed;
	} catch (e: unknown) {
		if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw e;
	}
}

export async function saveKeySnapshot(
	snapshot: KeySnapshot,
	path: string = resolveSnapshotPath(),
): Promise<void> {
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, JSON.stringify(snapshot, null, 2), { mode: 0o600 });
}

export function buildSnapshot(entities: Map<string, EntityKeyPair>): KeySnapshot {
	return {
		version: 1,
		createdAt: new Date().toISOString(),
		entities: Object.fromEntries(entities.entries()),
	};
}
