// Daily scan of every scheduled account at the configured UTC time, plus a
// catch-up scan shortly after startup for accounts whose last scan is more
// than a day old.

import type { Repo } from "./store/repo.ts";
import type { Scanner } from "./scanner.ts";

const TICK_MS = 60_000;
const CATCH_UP_DELAY_MS = 15_000;

export function startScheduler(repo: Repo, scanner: Scanner, log: (m: string) => void): () => void {
  const run = (trigger: string, ids: string[]) => {
    if (!ids.length) return;
    try {
      scanner.start(trigger, ids).done.catch(() => {
        /* logged by the scanner */
      });
    } catch (e) {
      log(`Scheduled scan not started: ${(e as Error).message}`);
    }
  };

  const tick = () => {
    const { schedule } = repo.settings.get();
    if (!schedule.enabled) return;
    const now = new Date();
    const due = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), schedule.hourUtc, schedule.minuteUtc);
    if (now.getTime() < due) return;
    run(
      "schedule",
      repo.accounts
        .list()
        .filter((a) => a.scheduled && !scanner.isBusy(a.id) && repo.scans.lastStarted(a.id) < due)
        .map((a) => a.id),
    );
  };

  const catchUp = setTimeout(() => {
    if (!repo.settings.get().schedule.enabled) return;
    run(
      "catch-up",
      repo.accounts
        .list()
        .filter((a) => {
          const last = repo.scans.lastStarted(a.id);
          return a.scheduled && last && Date.now() - last > 24 * 3600_000;
        })
        .map((a) => a.id),
    );
  }, CATCH_UP_DELAY_MS);
  const interval = setInterval(tick, TICK_MS);
  catchUp.unref();
  interval.unref();
  return () => {
    clearTimeout(catchUp);
    clearInterval(interval);
  };
}
