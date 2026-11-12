// First run: pick the platform, create its credential there, then choose the
// accounts to scan. Someone who uses one platform sees only that one's steps.

import { useState } from "react";
import { LayerCard } from "@cloudflare/kumo";
import { EyeIcon, HardDrivesIcon, LockKeyIcon } from "@phosphor-icons/react";
import { Wordmark } from "../components/brand.tsx";
import { ConnectForm, ProviderPicker, TokenHelp } from "../components/connect.tsx";
import { Card } from "../components/ui.tsx";
import { PROVIDER_INFO, PROVIDERS, providerList, withArticle, type ProviderId } from "../lib.ts";

export function SetupPage({ onDone }: { onDone: () => void }) {
  const [provider, setProvider] = useState<ProviderId>(PROVIDERS[0]);
  const info = PROVIDER_INFO[provider];
  return (
    <div className="min-h-full bg-kumo-canvas">
      <div className="flex h-14 items-center border-b border-kumo-hairline bg-kumo-base px-6">
        <Wordmark />
      </div>
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6 md:p-8 lg:py-9">
        <header>
          <h1 className="m-0 text-3xl font-semibold text-kumo-default">Connect your accounts</h1>
          <p className="mt-1.5 text-lg leading-normal text-pretty text-kumo-subtle">
            Keelson scans your configuration on {providerList()} for security problems and best-practice gaps, then tracks them until they're fixed.
          </p>
        </header>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Assurance icon={<EyeIcon />} title="Read-only" text="It never changes anything in your accounts." />
          <Assurance icon={<HardDrivesIcon />} title="Stays here" text="Results and tokens stay on this machine." />
          <Assurance
            icon={<LockKeyIcon />}
            title="No telemetry"
            text={`It talks to ${info.label}, and checks your own hostnames for takeovers (you can turn that off).`}
          />
        </div>

        <Card title="1. Choose a platform">
          <ProviderPicker value={provider} onChange={setProvider} />
        </Card>
        <Card title={`2. Create ${info.readOnlyCredential ? `a read-only ${info.credential}` : withArticle(info.credential)}`}>
          <TokenHelp provider={provider} />
        </Card>
        <Card title={`3. Paste it and choose ${info.accounts}`}>
          <ConnectForm key={provider} provider={provider} entities={[]} onConnected={onDone} />
        </Card>

        <p className="text-sm text-kumo-subtle">
          You can add more later from <span className="font-medium text-kumo-default">Accounts</span>: other {info.accounts}, the same company's accounts on
          other platforms, or accounts that belong to a different company. Group them into entities and decide which ones appear together.
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
