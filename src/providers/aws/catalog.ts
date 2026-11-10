// The AWS check catalog, built from the modules in checks/index.ts.

import { AWS_MODULES, type AwsCheckId } from "./checks/index.ts";
import type { CheckMeta } from "../../core/checks/define.ts";
import type { AwsSourceKey } from "./sources.ts";

export interface AwsCheckDef extends CheckMeta<AwsSourceKey> {
  id: AwsCheckId;
}

export const AWS_CHECKS: AwsCheckDef[] = AWS_MODULES.flatMap((m) =>
  Object.entries(m.meta).map(([id, meta]) => ({ id: id as AwsCheckId, ...(meta as CheckMeta<AwsSourceKey>) })),
);

export const AWS_CHECK_BY_ID: Record<string, AwsCheckDef> = Object.fromEntries(AWS_CHECKS.map((c) => [c.id, c]));
