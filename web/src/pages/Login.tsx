import { useState } from "react";
import { Banner, Button, LayerCard, SensitiveInput } from "@cloudflare/kumo";
import { XCircleIcon } from "@phosphor-icons/react";
import { api } from "../lib.ts";
import { Wordmark } from "../components/brand.tsx";

export function LoginPage({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api("/api/login", { method: "POST", body: { password } });
      onDone();
    } catch (x) {
      setErr((x as Error).message);
      setBusy(false);
    }
  };
  return (
    <div className="flex min-h-full items-center justify-center bg-kumo-canvas px-4">
      <form onSubmit={submit} className="w-full max-w-sm">
        <div className="mb-6 flex justify-center">
          <Wordmark />
        </div>
        <LayerCard>
          <LayerCard.Secondary>Sign in</LayerCard.Secondary>
          <LayerCard.Primary className="flex flex-col gap-4">
            <SensitiveInput
              label="Admin password"
              value={password}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
            {err && <Banner variant="error" size="sm" icon={<XCircleIcon weight="fill" />} title={err} />}
            <Button type="submit" variant="primary" loading={busy} disabled={!password}>
              Sign in
            </Button>
          </LayerCard.Primary>
        </LayerCard>
      </form>
    </div>
  );
}
