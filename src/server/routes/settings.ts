// Instance-wide settings, check overrides and triage. These apply to every
// account; the check list's pass/fail counts follow the requested scope.

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { CHECKS, CHECK_BY_ID } from "../../core/catalog.ts";
import { checkStats, latestScans, scanMeta } from "../scope.ts";
import { fingerprints, mergeSettings, param, requireJson, severityOrNull, triagePatch } from "../validate.ts";
import { notFound } from "../errors.ts";
import type { CheckRow, ChecksResponse, Settings } from "../../shared/api.ts";

export function settingsRoutes(r: Routes, { repo, auth }: AppContext) {
  r.get("/api/settings", (c) => c.json(repo.settings.get() satisfies Settings));

  r.put("/api/settings", async (c) => {
    const next = mergeSettings(repo.settings.get(), await requireJson(c));
    repo.settings.save(next);
    return c.json(next satisfies Settings);
  });

  r.get("/api/checks", (c) => {
    const scope = repo.resolveScope(c.req.query("scope") || "all");
    const scans = scope ? latestScans(repo, scope) : [];
    const stats = checkStats(scans);
    const o = repo.settings.overrides();
    return c.json({
      scan: scanMeta(scans),
      checks: CHECKS.map(
        (d): CheckRow => ({
          id: d.id,
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
