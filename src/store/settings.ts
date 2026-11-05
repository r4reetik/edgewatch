// Instance-wide settings and per-check overrides.

import type { Store } from "./db.ts";
import type { Settings } from "../shared/api.ts";
import type { Severity } from "../shared/severity.ts";

export const DEFAULT_SETTINGS: Settings = {
  schedule: { enabled: true, hourUtc: 3, minuteUtc: 0 },
  retentionDays: 180,
  slaDays: { critical: 7, high: 30, medium: 90, low: 180 },
  probes: { takeover: true },
  baseUrl: "",
};

export interface Overrides {
  disabled: Set<string>;
  severity: Record<string, Severity>;
}

export class SettingsRepo {
  readonly #s: Store;
  constructor(store: Store) {
    this.#s = store;
  }

  get(): Settings {
    const saved = Object.fromEntries(this.#s.all<{ key: string; value: string }>("SELECT key, value FROM settings").map((r) => [r.key, JSON.parse(r.value)]));
    return {
      schedule: { ...DEFAULT_SETTINGS.schedule, ...(saved.schedule || {}) },
      retentionDays: saved.retentionDays ?? DEFAULT_SETTINGS.retentionDays,
      slaDays: { ...DEFAULT_SETTINGS.slaDays, ...(saved.slaDays || {}) },
      probes: { ...DEFAULT_SETTINGS.probes, ...(saved.probes || {}) },
      // 0.2 kept the link URL under notifications.
      baseUrl: saved.baseUrl ?? saved.notifications?.baseUrl ?? DEFAULT_SETTINGS.baseUrl,
    };
  }

  save(next: Settings): void {
    this.#s.tx(() => {
      for (const [k, v] of Object.entries(next)) {
        this.#s.run("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", k, JSON.stringify(v));
      }
    });
  }

  /** Raw saved value of a key, including keys from older versions. */
  raw(key: string): unknown {
    const r = this.#s.get<{ value: string }>("SELECT value FROM settings WHERE key = ?", key);
    return r ? JSON.parse(r.value) : undefined;
  }

  delete(key: string): void {
    this.#s.run("DELETE FROM settings WHERE key = ?", key);
  }

  overrides(): Overrides {
    const rows = this.#s.all<{ check_id: string; disabled: number; severity: string | null }>("SELECT * FROM check_overrides");
    return {
      disabled: new Set(rows.filter((r) => r.disabled).map((r) => r.check_id)),
      severity: Object.fromEntries(rows.filter((r) => r.severity).map((r) => [r.check_id, r.severity as Severity])),
    };
  }

  setOverride(checkId: string, disabled: boolean, severity: Severity | null): void {
    if (!disabled && !severity) this.#s.run("DELETE FROM check_overrides WHERE check_id = ?", checkId);
    else
      this.#s.run(
        "INSERT INTO check_overrides (check_id, disabled, severity) VALUES (?, ?, ?) ON CONFLICT(check_id) DO UPDATE SET disabled = excluded.disabled, severity = excluded.severity",
        checkId,
        disabled ? 1 : 0,
        severity,
      );
  }
}
