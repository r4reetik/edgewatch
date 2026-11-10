// Every AWS check module, in the order they run. Adding one: write it with
// defineChecks (./define.ts), list it here, and add a failing case to
// test/aws-cases.ts.

import identity from "./identity.ts";
import storage from "./storage.ts";
import network from "./network.ts";
import compute from "./compute.ts";
import data from "./data.ts";
import edge from "./edge.ts";
import dns from "./dns.ts";
import monitoring from "./monitoring.ts";
import cloudflareLinks from "./cloudflare-links.ts";
import type { CheckModule } from "../../../core/checks/define.ts";

export const AWS_MODULES = [identity, storage, network, compute, data, edge, dns, monitoring, cloudflareLinks] as const;

type IdsOf<M> = M extends CheckModule<infer Id, infer _C, infer _S> ? Id : never;
export type AwsCheckId = IdsOf<(typeof AWS_MODULES)[number]>;
