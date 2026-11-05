import { LayerCard } from "@cloudflare/kumo";
import { EyeIcon, HardDrivesIcon, LockKeyIcon } from "@phosphor-icons/react";
import { Wordmark } from "../components/brand.tsx";
import { ConnectForm, TokenHelp } from "../components/connect.tsx";
import { Card } from "../components/ui.tsx";

export function SetupPage({ onDone }: { onDone: () => void }) {
  return (
    <div className="min-h-full bg-kumo-canvas">
      <div className="flex h-14 items-center border-b border-kumo-hairline bg-kumo-base px-6">
        <Wordmark />
      </div>
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6 md:p-8 lg:py-9">
        <header>
          <h1 className="m-0 text-3xl font-semibold text-kumo-default">Connect your Cloudflare accounts</h1>
          <p className="mt-1.5 text-lg leading-normal text-pretty text-kumo-subtle">
            Edgewatch scans your accounts' configuration for security problems and best-practice gaps, then tracks them until they're fixed.
          </p>
        </header>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Assurance icon={<EyeIcon />} title="Read-only" text="It never changes anything in your account." />
          <Assurance icon={<HardDrivesIcon />} title="Stays here" text="Results and the token stay on this machine." />
          <Assurance
            icon={<LockKeyIcon />}
            title="No telemetry"
            text="It talks to Cloudflare, and checks your own hostnames for takeovers (you can turn that off)."
          />
        </div>

        <Card title="1. Create a read-only API token">
          <TokenHelp />
        </Card>
        <Card title="2. Paste it and choose accounts">
          <ConnectForm entities={[]} onConnected={onDone} />
        </Card>

        <p className="text-sm text-kumo-subtle">
          You can add more accounts later from <span className="font-medium text-kumo-default">Accounts</span>, with this token or others, including accounts
          that belong to a different company. Group them into entities and decide which ones appear together.
        </p>
      </div>
    </div>
  );
}

function Assurance({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return (
    <LayerCard className="flex h-full flex-col gap-1 p-4">
      <div className="flex items-center gap-2 text-base font-medium text-kumo-default">
        <span className="text-kumo-brand">{icon}</span>
        {title}
      </div>
      <p className="text-sm text-kumo-subtle">{text}</p>
    </LayerCard>
  );
}
