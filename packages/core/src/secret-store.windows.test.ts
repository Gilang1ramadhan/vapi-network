import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { secretStore } from "./secret-store.js";
import { loadOrCreateDeviceKey } from "./vault-key.js";
import { createVault, openVault } from "./vault.js";

const POWERSHELL_TIMEOUT_MS = 60_000;

// The other store tests answer from a script, so only this file proves that
// Windows PowerShell really runs what the store sends. CI runs it on Windows.
describe.runIf(process.platform === "win32")("Windows Data Protection on a real machine", () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "vapi-dpapi-"));
    vi.stubEnv("LOCALAPPDATA", directory);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    rmSync(directory, { recursive: true, force: true });
  });

  it(
    "stores, reads and removes a secret",
    async () => {
      const store = secretStore();

      expect(store.available).toBe(true);
      await expect(store.get("main")).resolves.toBeUndefined();
      await expect(store.has("main")).resolves.toBe(false);
      await expect(store.remove("main")).resolves.toBe(false);

      await store.set("main", "pässwörd ✓");

      await expect(store.has("main")).resolves.toBe(true);
      await expect(store.get("main")).resolves.toBe("pässwörd ✓");
      await expect(store.remove("main")).resolves.toBe(true);
      await expect(store.get("main")).resolves.toBeUndefined();
    },
    POWERSHELL_TIMEOUT_MS,
  );

  it(
    "opens a new vault again with the device key it was created under",
    async () => {
      const path = join(directory, "vault.json");
      const key = await loadOrCreateDeviceKey({ secrets: secretStore() });
      await createVault({ path, key });

      const reloaded = await loadOrCreateDeviceKey({ secrets: secretStore() });

      expect(Buffer.from(reloaded).equals(Buffer.from(key))).toBe(true);
      await expect(openVault({ path, key: reloaded })).resolves.toBeDefined();
    },
    POWERSHELL_TIMEOUT_MS,
  );
});
