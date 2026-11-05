// Instance-wide settings. Every control saves as soon as it changes, like the
// switches on the Accounts and Checks pages; text fields save when they lose focus.

import { useState } from "react";
import { Input, Link, Select, Switch, useKumoToastManager } from "@cloudflare/kumo";
import { api, link, SCORED_SEVERITIES, SEVERITY_LABEL, useApi, type Settings } from "../lib.ts";
import { Card, FormGrid, Page, PageState, SettingRow, SettingRows } from "../components/ui.tsx";

const TITLE = "Settings";
const DESCRIPTION = "Scan schedule, history and how findings are tracked. These apply to every account.";
const HOURS = Object.fromEntries(Array.from({ length: 24 }, (_, h) => [String(h), `${String(h).padStart(2, "0")}:00 UTC`]));
type Save = (patch: Record<string, unknown>, label: string) => Promise<boolean>;

export function SettingsPage() {
  const { data, error, loading, reload, setData } = useApi<Settings>("/api/settings");
  const toasts = useKumoToastManager();

  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;

  const save: Save = async (patch, label) => {
    try {
      setData(await api<Settings>("/api/settings", { method: "PUT", body: patch }));
      toasts.add({ title: `${label} saved`, variant: "success" });
      return true;
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
      void reload();
      return false;
    }
  };

  return (
    <Page title={TITLE} description={DESCRIPTION}>
      <ScansCard s={data} save={save} />
      <PolicyCard s={data} save={save} />
      <LinksCard s={data} save={save} />
    </Page>
  );
}

/** A number field that saves on blur or Enter, and only when the value changed and is valid. */
function NumberField({
  label,
  value,
  min,
  max,
  unit,
  onSave,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  unit?: string;
  onSave: (n: number) => void;
}) {
  const [v, setV] = useState(String(value));
  const n = Number(v);
  const valid = Number.isInteger(n) && n >= min && n <= max;
  const commit = () => {
    if (valid && n !== value) onSave(n);
    else if (!valid) setV(String(value));
  };
  return (
    <div className="flex items-center gap-2">
      <Input
        aria-label={label}
        className="w-full"
        type="number"
        min={min}
        max={max}
        value={v}
        onChange={(e) => setV(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") commit();
        }}
        variant={valid ? "default" : "error"}
      />
      {unit && <span className="shrink-0 text-sm text-kumo-subtle">{unit}</span>}
    </div>
  );
}

function ScansCard({ s, save }: { s: Settings; save: Save }) {
  return (
    <Card title="Scans">
      <SettingRows>
        <SettingRow
          end
          title="Daily scan"
          description="Scan every account once a day, one after another. Accounts can be left out of the daily scan on the Accounts page. You can always run a scan by hand."
        >
          <Switch
            aria-label="Daily scan"
            checked={s.schedule.enabled}
            onCheckedChange={(v: boolean) => save({ schedule: { enabled: v } }, v ? "Daily scan on" : "Daily scan off")}
          />
        </SettingRow>
        <SettingRow title="Time" description="When the daily scan starts. A missed scan runs shortly after Edgewatch next starts.">
          <Select
            aria-label="Scan time"
            className="w-full"
            value={String(s.schedule.hourUtc)}
            items={HOURS}
            disabled={!s.schedule.enabled}
            onValueChange={(v) => save({ schedule: { hourUtc: Number(v), minuteUtc: 0 } }, "Scan time")}
          />
        </SettingRow>
        <SettingRow
          end
          title="Confirm subdomain takeovers"
          description="Sends one plain GET to each of your hostnames that points at a cloud provider (S3, Vercel, Heroku, GitHub Pages and others) and checks for that provider's 'doesn't exist' page. Turn off to keep every request inside Cloudflare's API."
        >
          <Switch
            aria-label="Confirm subdomain takeovers"
            checked={s.probes.takeover}
            onCheckedChange={(v: boolean) => save({ probes: { takeover: v } }, v ? "Takeover checks on" : "Takeover checks off")}
          />
        </SettingRow>
        <SettingRow title="History" description="How long to keep each account's scans. The latest scan is always kept.">
          <NumberField
            key={s.retentionDays}
            label="Days of history"
            value={s.retentionDays}
            min={7}
            max={3650}
            unit="days"
            onSave={(n) => save({ retentionDays: n }, "History")}
          />
        </SettingRow>
      </SettingRows>
    </Card>
  );
}

function PolicyCard({ s, save }: { s: Settings; save: Save }) {
  return (
    <Card
      title="Findings policy"
      description={
        <>
          Company email domains, used to spot outside members and Access rules, are set per entity on the <Link {...link("/accounts")}>Accounts page</Link>.
        </>
      }
    >
      <SettingRows>
        <SettingRow title="Days to fix (SLA)" description="Findings without a due date are flagged overdue after this many days, by severity.">
          <FormGrid cols={4}>
            {SCORED_SEVERITIES.map((k) => (
              <div key={`${k}-${s.slaDays[k]}`} className="flex flex-col gap-1.5">
                <span className="text-sm font-medium text-kumo-default">{SEVERITY_LABEL[k]}</span>
                <NumberField
                  label={`${SEVERITY_LABEL[k]} SLA in days`}
                  value={s.slaDays[k]}
                  min={1}
                  max={3650}
                  onSave={(n) => save({ slaDays: { [k]: n } }, `${SEVERITY_LABEL[k]} SLA`)}
                />
              </div>
            ))}
          </FormGrid>
        </SettingRow>
      </SettingRows>
    </Card>
  );
}

function LinksCard({ s, save }: { s: Settings; save: Save }) {
  const [baseUrl, setBaseUrl] = useState(s.baseUrl || "");
  const commit = () => {
    if (baseUrl.trim().replace(/\/$/, "") !== (s.baseUrl || "")) void save({ baseUrl }, "Link URL");
  };
  return (
    <Card
      title="Notifications"
      description={
        <>
          Each entity sends its own accounts' alerts to its own Slack channel or webhook, so alerts never cross between companies. Set them on the{" "}
          <Link {...link("/accounts")}>Accounts page</Link>.
        </>
      }
    >
      <SettingRows>
        <SettingRow title="Link URL" description="Optional. The address people use to open Edgewatch, so alerts can link straight to each finding.">
          <Input
            aria-label="Edgewatch URL"
            className="w-full"
            placeholder="https://edgewatch.internal.example.com"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
              if (e.key === "Enter") commit();
            }}
          />
        </SettingRow>
      </SettingRows>
    </Card>
  );
}
