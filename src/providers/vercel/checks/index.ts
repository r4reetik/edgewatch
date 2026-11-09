// Every Vercel check module, in the order they run. Adding one: write it with
// defineChecks (./define.ts), list it here, and add a failing case to
// test/vercel-cases.ts.

import identity from "./identity.ts";
import deployments from "./deployments.ts";
import secrets from "./secrets.ts";
import firewall from "./firewall.ts";
import domains from "./domains.ts";
import monitoring from "./monitoring.ts";
import platform from "./platform.ts";
import cloudflareLinks from "./cloudflare-links.ts";
import type { CheckModule } from "../../../core/checks/define.ts";

export const VERCEL_MODULES = [identity, deployments, secrets, firewall, domains, monitoring, platform, cloudflareLinks] as const;

type IdsOf<M> = M extends CheckModule<infer Id, infer _C, infer _S> ? Id : never;
export type VercelCheckId = IdsOf<(typeof VERCEL_MODULES)[number]>;
