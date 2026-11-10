// What an AWS scan collects: the fields checks read, typed from the AWS API
// references. Payloads are trimmed when they're read, so the inventory never holds
// a secret access key, a Lambda environment variable or a policy document: only
// what was concluded from them.

import type { AwsSourceKey } from "./sources.ts";
import type { Prefixes } from "../../core/aws-ranges.ts";

/** The name findings use for resources that aren't in a region (IAM, S3 settings, CloudFront, Route 53). */
export const GLOBAL = "Global";

export interface AwsAccessKey {
  /** The last four characters of the key ID, enough to find it in the console. */
  hint: string;
  active: boolean;
  createdAt: number | null;
  lastUsedAt: number | null;
}

export interface AwsUser {
  name: string;
  createdAt: number | null;
  /** Whether the user can sign in to the console; null when it couldn't be read. */
  console: boolean | null;
  passwordLastUsedAt: number | null;
  mfa: boolean | null;
  keys: AwsAccessKey[] | null;
}

/** Who holds administrator access, from the account's authorization details. */
export interface AwsAdmin {
  user: string;
  /** How: "AdministratorAccess", "group Admins", "inline policy". */
  via: string;
}

/** One principal a role's trust policy lets assume it. */
export interface AwsTrust {
  /** "*", an account ID, a role or user ARN, a service or a federated provider. */
  principal: string;
  kind: "anyone" | "account" | "service" | "federated";
  /** The statement has a Condition (an external ID, an organization, MFA…). */
  conditional: boolean;
}

export interface AwsRole {
  name: string;
  trust: AwsTrust[];
  admin: boolean;
  /** Created by AWS for one of its services. */
  serviceLinked: boolean;
  /** Instance profiles that hand this role to EC2 instances. */
  profiles: string[];
  /** When the role was last assumed; null when never, or more than 400 days ago (AWS's tracking window). */
  lastUsedAt: number | null;
}

export interface AwsPolicy {
  name: string;
  /** Allows every action on every resource. */
  fullAdmin: boolean;
  attachments: number;
}

export interface PublicAccessBlock {
  blockPublicAcls: boolean;
  ignorePublicAcls: boolean;
  blockPublicPolicy: boolean;
  restrictPublicBuckets: boolean;
}

export interface AwsBucket {
  name: string;
  region: string;
  /** undefined: unreadable. null: the bucket has no setting of its own. */
  block: PublicAccessBlock | null | undefined;
  /** Whether AWS judges the bucket policy public. null: no policy. undefined: unreadable. */
  policyPublic: boolean | null | undefined;
  /** Groups the ACL grants access to: "everyone", "any AWS account". undefined: unreadable. */
  aclPublic: string[] | undefined;
}

export interface AwsSecurityGroup {
  id: string;
  name: string;
  vpcId: string | null;
  /** Inbound rules that allow the whole internet (0.0.0.0/0 or ::/0). */
  open: { protocol: string; from: number | null; to: number | null; cidr: string }[];
}

export interface AwsInstance {
  id: string;
  name: string | null;
  running: boolean;
  publicIp: string | null;
  vpcId: string | null;
  securityGroups: string[];
  /** IMDSv2 is required (HttpTokens = required). null: the metadata service is off. */
  imdsV2: boolean | null;
  /** The instance profile attached to it, which names the role its software runs as. */
  profile: string | null;
  /** The kind of credential found in its start-up script (user data). null: none. undefined: not read. The script itself is never kept. */
  userDataSecret: string | null | undefined;
}

/** A network interface: what a security group is really attached to, and whether it has a public address. */
export interface AwsInterface {
  id: string;
  publicIp: string | null;
  securityGroups: string[];
  /** What owns it: "instance", "load balancer", "database", "NAT gateway", "Lambda", or AWS's own type. */
  kind: string;
  /** The instance ID, or AWS's description of the owner. */
  owner: string | null;
}

export interface AwsDatabase {
  id: string;
  engine: string;
  public: boolean;
  encrypted: boolean;
  backupDays: number;
  /** A read replica: its backups are the source database's. */
  replica: boolean;
  vpcId: string | null;
  securityGroups: string[];
  port: number | null;
}

export interface AwsListener {
  port: number | null;
  protocol: string;
  sslPolicy: string | null;
  /** The default action sends visitors to HTTPS. */
  redirects: boolean;
}

export interface AwsLoadBalancer {
  name: string;
  dnsName: string;
  type: string;
  internetFacing: boolean;
  vpcId: string | null;
  /** Empty for network load balancers without their own groups: their targets' groups decide. */
  securityGroups: string[];
  /** Whether access logs are written; null when it couldn't be read. */
  accessLogs: boolean | null;
  listeners: AwsListener[] | null;
}

export interface AwsFunction {
  name: string;
  runtime: string | null;
  /** The name of its execution role. */
  role: string | null;
  /** Function URLs by auth type ("NONE", "AWS_IAM"); null when they couldn't be read. */
  urls: { authType: string }[] | null;
}

export interface AwsRegion {
  name: string;
  securityGroups: AwsSecurityGroup[] | null;
  instances: AwsInstance[] | null;
  ebsEncryptionByDefault: boolean | null;
  publicSnapshots: string[] | null;
  publicImages: { id: string; name: string | null }[] | null;
  vpcs: { id: string; isDefault: boolean; flowLogs: boolean | null }[] | null;
  databases: AwsDatabase[] | null;
  loadBalancers: AwsLoadBalancer[] | null;
  functions: AwsFunction[] | null;
  /** Every network interface in the region; null when unreadable. */
  interfaces: AwsInterface[] | null;
  /** Elastic IPs allocated in the region, attached or not; null when unreadable. */
  addresses: string[] | null;
  /** CloudFront domain names AWS runs for API Gateway custom domains: they aren't in the account's distributions. null when unreadable. */
  apiDomains: string[] | null;
  /** Whether a GuardDuty detector is on; null when it couldn't be read. */
  guardDuty: boolean | null;
}

export interface AwsDistribution {
  id: string;
  domainName: string;
  enabled: boolean;
  aliases: string[];
  /** Viewer protocol policies across its behaviours ("allow-all", "redirect-to-https", "https-only"). */
  viewerPolicies: string[];
  minTls: string | null;
  defaultCertificate: boolean;
  waf: boolean;
  /** `restricted`: an S3 origin read through origin access control (or the older origin access identity), so the bucket can stay private. */
  origins: { domain: string; protocolPolicy: string | null; s3: boolean; restricted: boolean }[];
}

export interface AwsRecord {
  name: string;
  type: string;
  /** Record values, or the alias target. Trailing dots removed, lowercase. */
  targets: string[];
  alias: boolean;
}

export interface AwsHostedZone {
  id: string;
  name: string;
  private: boolean;
  records: AwsRecord[] | null;
}

export interface AwsInventory {
  accountId: string;
  /** The account alias, when it has one. */
  accountName: string | null;
  now: number;
  unreadable: AwsSourceKey[];
  /** Whether the access key belongs to the root user. */
  rootKey: boolean;
  root: { mfa: boolean; accessKeys: boolean; users: number } | null;
  /** undefined: unreadable. null: the account has no password policy. */
  passwordPolicy:
    | { minLength: number; symbols: boolean; numbers: boolean; uppercase: boolean; lowercase: boolean; reusePrevention: number | null }
    | null
    | undefined;
  users: AwsUser[] | null;
  admins: AwsAdmin[] | null;
  roles: AwsRole[] | null;
  policies: AwsPolicy[] | null;
  /** undefined: unreadable. null: never set. */
  s3Block: PublicAccessBlock | null | undefined;
  buckets: AwsBucket[] | null;
  /** Regions that were read. */
  regions: AwsRegion[];
  /** Enabled regions that refused the access key (a service control policy, usually): nothing there was evaluated. */
  skippedRegions: string[];
  distributions: AwsDistribution[] | null;
  hostedZones: AwsHostedZone[] | null;
  /** Addresses this account was seen to give up on earlier scans, with when (set by the provider from the previous scan). */
  released: { ip: string; at: string }[];
  /** AWS's published EC2 address ranges, to recognise a record that points at an AWS address. Held for the scan, never stored. */
  ec2Prefixes: Prefixes | null;
}

export type { Related } from "../../core/types.ts";
