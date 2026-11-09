// Every check module, in the order they run. Adding a module: write it with
// defineChecks (see define.ts) and list it here; test/checks/cases.ts then needs
// a failing fixture for each new check ID.

import attackSurface from "./attack-surface.ts";
import traffic from "./traffic.ts";
import iam from "./iam.ts";
import zeroTrust from "./zero-trust.ts";
import tls from "./tls.ts";
import waf from "./waf.ts";
import wafRules from "./waf-rules.ts";
import dns from "./dns.ts";
import email from "./email.ts";
import platform from "./platform.ts";
import monitoring from "./monitoring.ts";
import changeRisk from "./change-risk.ts";
import cost from "./cost.ts";
import vercelLinks from "./vercel-links.ts";
import type { CheckModule } from "./define.ts";

export const MODULES = [iam, zeroTrust, tls, waf, wafRules, dns, email, platform, monitoring, attackSurface, traffic, changeRisk, cost, vercelLinks] as const;

type IdsOf<M> = M extends CheckModule<infer Id> ? Id : never;
/** Every check ID, as a type: report("TLS-05", …) or CASES["TLS-05"] doesn't compile. */
export type CheckId = IdsOf<(typeof MODULES)[number]>;
