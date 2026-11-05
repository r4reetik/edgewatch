// Entities: the companies or teams that own accounts, with their own email
// domains, alert destinations, and whether they appear in "All accounts".

import type { AppContext } from "../env.ts";
import type { Routes } from "../router.ts";
import { sendTest } from "../../notify.ts";
import { publicEntity } from "../present.ts";
import { direction, mergeEntity, param, readJson, requireJson, requiredName } from "../validate.ts";
import { badRequest, conflict, notFound } from "../errors.ts";

export function entityRoutes(r: Routes, { repo }: AppContext) {
  const entity = (id: string) =>
    repo.entities.get(Number(id)) ??
    (() => {
      throw notFound("Unknown entity");
    })();

  r.post("/api/entities", async (c) => {
    const body = await readJson(c);
    const e = repo.entities.create(requiredName(body?.name), { includeInAll: body?.includeInAll !== false });
    return c.json({ ok: true, entity: publicEntity(e) });
  });

  r.patch("/api/entities/:id", async (c) => {
    const e = entity(param(c, "id"));
    const body = await requireJson(c);
    repo.entities.update(e.id, mergeEntity(e, body));
    if (body.move !== undefined) repo.entities.move(e.id, direction(body.move));
    return c.json({ ok: true, entity: publicEntity(repo.entities.get(e.id)!) });
  });

  r.delete("/api/entities/:id", (c) => {
    const e = entity(param(c, "id"));
    if (repo.accounts.list().some((a) => a.entityId === e.id)) throw conflict("Move or remove this entity's accounts first.");
    repo.entities.delete(e.id);
    return c.json({ ok: true });
  });

  r.post("/api/entities/:id/test-notification", async (c) => {
    const e = entity(param(c, "id"));
    if (!e.notifications.slackWebhookUrl && !e.notifications.webhookUrl) throw badRequest("Add a Slack or webhook URL first.");
    return c.json(await sendTest(e.notifications, repo.settings.get().baseUrl, e.name));
  });
}
