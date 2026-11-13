// Instance-wide settings, update checks, check overrides and triage. These apply
// to every account; the check list's pass/fail counts follow the requested scope.

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { CHECKS, CHECK_BY_ID } from "../../providers/catalog.ts";
import { PROVIDERS } from "../../shared/providers.ts";
import { checkStats, latestScans, scanMeta } from "../scope.ts";
import { fingerprints, mergeSettings, param, requireJson, severityOrNull, triagePatch } from "../validate.ts";
import { notFound } from "../errors.ts";
import type { CheckRow, ChecksResponse, OwnersResponse, Settings, UpdateStatus } from "../../shared/api.ts";
import { UpdateChecker } from "../../updates.ts";

export function settingsRoutes(r: Routes, { repo, auth, version, updates }: AppContext) {
  // Without a checker (tests, the mock server) updates read as switched off.
  const checker = updates ?? new UpdateChecker({ version, repository: null, install: "source", enabled: () => false });

  r.get("/api/settings", (c) => c.json(repo.settings.get() satisfies Settings));

  r.put("/api/settings", async (c) => {
    const before = repo.settings.get();
    const next = mergeSettings(before, await requireJson(c));
    repo.settings.save(next);
    // Turning checks on shouldn't mean waiting a day for the first one.
    if (next.updates.check && !before.updates.check) void checker.check();
    return c.json(next satisfies Settings);
  });

  r.get("/api/updates", (c) => c.json(checker.status() satisfies UpdateStatus));
  r.post("/api/updates/check", async (c) => c.json((await checker.check()) satisfies UpdateStatus));

  r.get("/api/checks", (c) => {
    const scope = repo.resolveScope(c.req.query("scope") || "all");
    const scans = scope ? latestScans(repo, scope) : [];
    const stats = checkStats(scans);
    const o = repo.settings.overrides();
    // Only the providers in view: someone on one platform doesn't need the others' checks listed.
    const shown = new Set(scope?.provider ? [scope.provider] : scope?.providers.length ? scope.providers : PROVIDERS);
    return c.json({
      scan: scanMeta(scans),
      checks: CHECKS.filter((d) => shown.has(d.provider)).map(
        (d): CheckRow => ({
          id: d.id,
          provider: d.provider,
          spans: d.spans ?? [],
          category: d.category,
          severity: d.severity,
          title: d.title,
          why: d.why,
          fix: d.fix,
          docs: d.docs ?? null,
          requires: d.requires ?? [],
          ...(stats[d.id] || { evaluated: 0, failed: 0 }),
          disabled: o.disabled.has(d.id),
          severityOverride: o.severity[d.id] || null,
        }),
      ),
    } satisfies ChecksResponse);
  });

  r.put("/api/checks/:id", async (c) => {
    const id = param(c, "id");
    if (!CHECK_BY_ID[id]) throw notFound("Unknown check");
    const body = await requireJson(c);
    repo.settings.setOverride(id, !!body.disabled, severityOrNull(body.severity));
    return c.json({ ok: true });
  });

  // Owners to suggest when triaging findings in these accounts (comma-separated ids). An entity is one
  // company, so suggestions come from every account in the same entities and never from other companies.
  r.get("/api/owners", (c) => {
    const all = repo.accounts.list();
    const asked = new Set((c.req.query("accounts") || "").split(",").filter(Boolean));
    const entities = new Set(all.filter((a) => asked.has(a.id)).map((a) => a.entityId));
    const ids = all.filter((a) => entities.has(a.entityId)).map((a) => a.id);
    return c.json({ owners: repo.findings.owners(ids) } satisfies OwnersResponse);
  });

  // PUT /api/triage/:fp for one finding; POST /api/triage with { fingerprints } for many.
  r.on(["PUT", "POST"], ["/api/triage/:fp", "/api/triage"], async (c) => {
    const body = await requireJson(c);
    const one = c.req.param("fp");
    const fps = fingerprints(one ? [one] : body.fingerprints);
    const { patch, appendNote } = triagePatch(body);
    repo.findings.setTriage(fps, patch, auth.required ? "admin" : "local", { appendNote });
    return c.json({ ok: true, updated: fps.length });
  });
}
