// How AWS check modules are written: the same shape as the other providers' (see
// src/core/checks/define.ts), over an AWS inventory.
//
//   export default defineChecks({
//     "AID-001": { category: "Identity & access", severity: "critical", title: "…", why: "…", fix: "…", requires: ["iamSummary"] },
//   }, ({ inv, d }, report) => {
//     if (inv.root) report("AID-001", { zone: GLOBAL, resource: "root user", pass: inv.root.mfa, link: d.rootCredentials });
//   });
//
// A finding's `zone` is its region, or "Global" for IAM, S3, CloudFront and Route 53.

import { checksFor } from "../../../core/checks/define.ts";
import type { EngineOptions } from "../../../core/types.ts";
import type { AwsSourceKey } from "../sources.ts";
import type { AwsInterface, AwsInventory, AwsRegion, AwsRole, AwsSecurityGroup, Related } from "../types.ts";

export interface AwsContext {
  inv: AwsInventory;
  opts: EngineOptions;
  /** Links into the AWS console. */
  d: typeof dash;
  /** What the entity's other accounts share, for checks that span providers. */
  related: Related;
}

export const defineChecks = checksFor<AwsContext, AwsSourceKey>();

const regional = (region: string, service: string, hash: string) => `https://${region}.console.aws.amazon.com/${service}/home?region=${region}#${hash}`;
const iam = (hash: string) => `https://console.aws.amazon.com/iam/home#/${hash}`;

export const dash = {
  rootCredentials: iam("security_credentials"),
  accountSettings: iam("account_settings"),
  user: (name: string) => iam(`users/details/${encodeURIComponent(name)}?section=security_credentials`),
  role: (name: string) => iam(`roles/details/${encodeURIComponent(name)}?section=trust_relationships`),
  policies: iam("policies"),
  s3Settings: "https://s3.console.aws.amazon.com/s3/settings",
  bucket: (name: string) => `https://s3.console.aws.amazon.com/s3/buckets/${encodeURIComponent(name)}?tab=permissions`,
  securityGroup: (region: string, id: string) => regional(region, "ec2", `SecurityGroup:groupId=${id}`),
  instance: (region: string, id: string) => regional(region, "ec2", `InstanceDetails:instanceId=${id}`),
  ebsSettings: (region: string) => regional(region, "ec2", "Settings:tab=dataProtectionAndSecurity"),
  snapshot: (region: string, id: string) => regional(region, "ec2", `SnapshotDetails:snapshotId=${id}`),
  image: (region: string, id: string) => regional(region, "ec2", `ImageDetails:imageId=${id}`),
  vpc: (region: string, id: string) => regional(region, "vpcconsole", `VpcDetails:VpcId=${id}`),
  database: (region: string, id: string) => regional(region, "rds", `database:id=${encodeURIComponent(id)}`),
  loadBalancers: (region: string) => regional(region, "ec2", "LoadBalancers:"),
  lambda: (region: string, name: string) => regional(region, "lambda", `/functions/${encodeURIComponent(name)}?tab=configure`),
  guardDuty: (region: string) => regional(region, "guardduty", "/"),
  distribution: (id: string) => `https://console.aws.amazon.com/cloudfront/v4/home#/distributions/${id}`,
  hostedZone: (id: string) => `https://console.aws.amazon.com/route53/v2/hostedzones#ListRecordSets/${id}`,
};

/** A region that runs something: instances, databases, load balancers or functions. Per-region settings only matter there. */
export const inUse = (r: AwsRegion): boolean =>
  !!(r.instances?.some((i) => i.running) || r.databases?.length || r.loadBalancers?.length || r.functions?.length);

/** Whether an open rule of a security group covers a port. Protocol -1 is every port of every protocol. */
export function opens(g: AwsSecurityGroup, port: number): boolean {
  return g.open.some(
    (r) => r.protocol === "-1" || ((r.protocol === "tcp" || r.protocol === "6") && r.from != null && r.to != null && r.from <= port && port <= r.to),
  );
}

/** Whether a group lets the internet reach the web ports. */
export const opensWeb = (g: AwsSecurityGroup): boolean => opens(g, 443) || opens(g, 80);

/** The network interfaces a security group is attached to: what its rules really expose. */
export const usedBy = (region: AwsRegion, groupId: string): AwsInterface[] => (region.interfaces ?? []).filter((i) => i.securityGroups.includes(groupId));

/** The role an instance profile hands to its instances, or undefined when no role uses it. */
export const roleOfProfile = (inv: AwsInventory, profile: string | null): AwsRole | undefined =>
  profile ? inv.roles?.find((r) => r.profiles.includes(profile)) : undefined;

/** The 12-digit account in a trust policy's principal: an account ID, or the ARN of its root, a user or a role. */
export const accountOf = (principal: string): string | null =>
  /^(\d{12})$|^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):/.exec(principal)?.slice(1).find(Boolean) ?? null;

/** "tcp 22" or "tcp 8000-8100" or "all traffic", with where from. */
export const ruleText = (r: AwsSecurityGroup["open"][number]): string =>
  `${r.protocol === "-1" ? "all traffic" : `${r.protocol} ${r.from === r.to ? r.from : `${r.from}-${r.to}`}`} from ${r.cidr}`;

export const days = (from: number | null, now: number): number | null => (from == null ? null : Math.floor((now - from) / 86_400_000));
export const date = (t: number | null): string => (t ? new Date(t).toISOString().slice(0, 10) : "unknown");
