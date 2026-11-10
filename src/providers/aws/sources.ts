// Every AWS data source a scan reads. Like the other providers' registries, each
// source has a coverage label, what grants it, and an optional probe for the setup
// screen. `permission` names the IAM actions; AWS's managed SecurityAudit policy
// grants all of them and nothing that writes.

import type { AwsClient } from "./client.ts";

export interface AwsSource {
  label: string;
  /** The IAM actions that read it. */
  permission: string;
  /** A cheap request that proves the access key can read this source (setup screen). */
  probe?: (c: AwsClient) => Promise<unknown>;
  /** Read in every enabled region. A region that refuses (a service control policy, for example) is left out rather than failing the source. */
  regional?: boolean;
}

/** The region the global services (IAM, STS, CloudFront, Route 53) sign for, and where probes ask regional services. */
export const HOME_REGION = "us-east-1";

const iam =
  (action: string, params: Record<string, string> = {}) =>
  (c: AwsClient) =>
    c.query("iam", HOME_REGION, action, params);
const ec2 =
  (action: string, params: Record<string, string> = {}) =>
  (c: AwsClient) =>
    c.query("ec2", HOME_REGION, action, params);

const DEFS = {
  identity: { label: "Account identity", permission: "sts:GetCallerIdentity", probe: (c) => c.query("sts", HOME_REGION, "GetCallerIdentity") },
  iamSummary: { label: "IAM account summary (root user)", permission: "iam:GetAccountSummary", probe: iam("GetAccountSummary") },
  passwordPolicy: {
    label: "IAM password policy",
    permission: "iam:GetAccountPasswordPolicy",
    probe: (c) => c.optional(() => c.query("iam", HOME_REGION, "GetAccountPasswordPolicy")),
  },
  iamUsers: {
    label: "IAM users, their access keys and MFA devices",
    permission: "iam:ListUsers, iam:ListAccessKeys, iam:GetAccessKeyLastUsed, iam:ListMFADevices, iam:GetLoginProfile",
    probe: iam("ListUsers", { MaxItems: "1" }),
  },
  iamDetails: {
    label: "IAM roles, groups and policies",
    permission: "iam:GetAccountAuthorizationDetails",
    probe: iam("GetAccountAuthorizationDetails", { MaxItems: "1", "Filter.member.1": "LocalManagedPolicy" }),
  },
  s3Account: {
    label: "S3 Block Public Access for the account",
    permission: "s3:GetAccountPublicAccessBlock",
    probe: (c) => c.optional(() => c.s3Control("/v20180820/configuration/publicAccessBlock")),
  },
  s3Buckets: { label: "S3 buckets", permission: "s3:ListAllMyBuckets, s3:GetBucketLocation", probe: (c) => c.s3(HOME_REGION, "/", {}) },
  s3BucketAccess: {
    label: "S3 bucket access settings",
    permission: "s3:GetBucketPublicAccessBlock, s3:GetBucketPolicyStatus, s3:GetBucketAcl",
  },
  regions: { label: "Enabled regions", permission: "ec2:DescribeRegions", probe: ec2("DescribeRegions") },
  securityGroups: {
    label: "Security groups",
    permission: "ec2:DescribeSecurityGroups",
    probe: ec2("DescribeSecurityGroups", { MaxResults: "5" }),
    regional: true,
  },
  networkInterfaces: {
    label: "Network interfaces and Elastic IPs",
    permission: "ec2:DescribeNetworkInterfaces, ec2:DescribeAddresses",
    probe: ec2("DescribeAddresses"),
    regional: true,
  },
  instances: { label: "EC2 instances", permission: "ec2:DescribeInstances", probe: ec2("DescribeInstances", { MaxResults: "5" }), regional: true },
  ebs: {
    label: "EBS encryption, public snapshots and public images",
    permission: "ec2:GetEbsEncryptionByDefault, ec2:DescribeSnapshots, ec2:DescribeImages",
    probe: ec2("GetEbsEncryptionByDefault"),
    regional: true,
  },
  vpcs: { label: "VPCs and flow logs", permission: "ec2:DescribeVpcs, ec2:DescribeFlowLogs", probe: ec2("DescribeVpcs"), regional: true },
  databases: {
    label: "RDS databases",
    permission: "rds:DescribeDBInstances",
    probe: (c) => c.query("rds", HOME_REGION, "DescribeDBInstances", { MaxRecords: "20" }),
    regional: true,
  },
  loadBalancers: {
    label: "Load balancers and listeners",
    permission: "elasticloadbalancing:DescribeLoadBalancers, elasticloadbalancing:DescribeListeners, elasticloadbalancing:DescribeLoadBalancerAttributes",
    probe: (c) => c.query("elasticloadbalancing", HOME_REGION, "DescribeLoadBalancers", { PageSize: "1" }),
    regional: true,
  },
  functions: {
    label: "Lambda functions and function URLs",
    permission: "lambda:ListFunctions, lambda:ListFunctionUrlConfigs",
    probe: (c) => c.json("lambda", HOME_REGION, "/2015-03-31/functions/", { MaxItems: "1" }),
    regional: true,
  },
  userData: {
    label: "Instance start-up scripts (scanned for credentials, never stored)",
    permission: "ec2:DescribeInstanceAttribute",
    regional: true,
  },
  apiDomains: {
    label: "API Gateway custom domain names",
    permission: "apigateway:GET",
    probe: (c) => c.json("apigateway", HOME_REGION, "/domainnames", { limit: "1" }),
    regional: true,
  },
  guardduty: {
    label: "GuardDuty detectors",
    permission: "guardduty:ListDetectors, guardduty:GetDetector",
    probe: (c) => c.json("guardduty", HOME_REGION, "/detector", {}),
    regional: true,
  },
  cloudfront: {
    label: "CloudFront distributions",
    permission: "cloudfront:ListDistributions",
    probe: (c) => c.xml("cloudfront", HOME_REGION, "cloudfront.amazonaws.com", "/2020-05-31/distribution", { MaxItems: "1" }),
  },
  route53: {
    label: "Route 53 hosted zones and records",
    permission: "route53:ListHostedZones, route53:ListResourceRecordSets",
    probe: (c) => c.xml("route53", HOME_REGION, "route53.amazonaws.com", "/2013-04-01/hostedzone", { maxitems: "1" }),
  },
  ipRanges: { label: "AWS's published address ranges (ip-ranges.amazonaws.com)", permission: "None: a public file, read without the access key" },
} satisfies Record<string, AwsSource>;

export type AwsSourceKey = keyof typeof DEFS;
export const AWS_SOURCES: Record<AwsSourceKey, AwsSource> = DEFS;
export const AWS_SOURCE_KEYS = Object.keys(DEFS) as AwsSourceKey[];
