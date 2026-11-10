// One AWS scan's reads: who the access key is, IAM (the root user, the password
// policy, users with their keys and MFA, roles and policies), S3, every enabled
// region (security groups, instances, EBS, VPCs, databases, load balancers,
// functions, GuardDuty), CloudFront and Route 53.
//
// Secrets never enter the inventory: policy documents are reduced to what they
// allow, Lambda's environment variables are dropped with the rest of the payload,
// and only the last four characters of an access key ID are kept.

import { gunzipSync } from "node:zlib";
import { AwsError, type AwsClient, type Json } from "./client.ts";
import { AWS_SOURCES, AWS_SOURCE_KEYS, HOME_REGION, type AwsSourceKey } from "./sources.ts";
import { at, bool, find, items, text, time, type XmlNode } from "./xml.ts";
import type {
  AwsAdmin,
  AwsBucket,
  AwsDatabase,
  AwsDistribution,
  AwsFunction,
  AwsHostedZone,
  AwsInstance,
  AwsInterface,
  AwsInventory,
  AwsLoadBalancer,
  AwsPolicy,
  AwsRecord,
  AwsRegion,
  AwsRole,
  AwsSecurityGroup,
  AwsTrust,
  AwsUser,
  PublicAccessBlock,
} from "./types.ts";
import type { ProgressEvent } from "../../core/types.ts";
import { fetchEc2Prefixes } from "../../core/aws-ranges.ts";
import { secretKindIn } from "../../core/secret-patterns.ts";

const REGION_CONCURRENCY = 4;
const ITEM_CONCURRENCY = 6;
const MAX_PAGES = 50;
const MAX_USERS = 1000;
const MAX_BUCKETS = 1000;
const MAX_ZONES = 200;
/** Function URLs cost a request per function, so they're read only up to this many functions in a region. */
const MAX_FUNCTION_URLS = 150;
/** Start-up scripts cost a request per instance, so they're scanned only up to this many running instances in a region. */
const MAX_USER_DATA = 400;
/** AWS policies that amount to full control: IAMFullAccess can grant itself everything else. */
const ADMIN_POLICY = /:policy\/(AdministratorAccess|IAMFullAccess)$/;

export async function collectAws(client: AwsClient, onProgress: (p: ProgressEvent) => void = () => {}): Promise<AwsInventory> {
  onProgress({ phase: "Reading the account" });
  const identity = await client.query("sts", HOME_REGION, "GetCallerIdentity");
  client.note("identity", true);
  const accountId = text(find(identity, "Account")) ?? "";
  client.accountId = accountId;
  const rootKey = /:root$/.test(text(find(identity, "Arn")) ?? "");
  // The alias is only a display name: an account without one, or a key that can't read it, shows its ID.
  const accountName = await client
    .query("iam", HOME_REGION, "ListAccountAliases")
    .then((d) => text(find(d, "AccountAliases"), "member"))
    .catch(() => null);

  onProgress({ phase: "Reading IAM" });
  const [root, passwordPolicy, users, details] = await Promise.all([
    client.read("iamSummary", () => client.query("iam", HOME_REGION, "GetAccountSummary")).then((d) => (d ? toRoot(d) : null)),
    client.readOptional("passwordPolicy", () => client.query("iam", HOME_REGION, "GetAccountPasswordPolicy")).then((d) => (d ? toPasswordPolicy(d) : d)),
    readUsers(client),
    client.read("iamDetails", () => readDetails(client)),
  ]);

  onProgress({ phase: "Reading S3" });
  const [s3Block, buckets] = await Promise.all([
    client.readOptional("s3Account", () => client.s3Control("/v20180820/configuration/publicAccessBlock")).then((d) => (d ? toBlock(d) : d)),
    readBuckets(client),
  ]);

  onProgress({ phase: "Reading regions" });
  const regionDoc = await client.read("regions", () => client.query("ec2", HOME_REGION, "DescribeRegions"));
  const names = regionDoc ? items(find(regionDoc, "regionInfo")).flatMap((r) => text(r, "regionName") ?? []) : [HOME_REGION];
  const regions: AwsRegion[] = [];
  const skippedRegions: string[] = [];
  let refusal: unknown = null;
  let done = 0;
  await pool(names, REGION_CONCURRENCY, async (name) => {
    try {
      regions.push(await readRegion(client, name));
    } catch (e) {
      skippedRegions.push(name);
      refusal ??= e;
    }
    onProgress({ phase: "Reading regions", done: ++done, total: names.length });
  });
  regions.sort((a, b) => a.name.localeCompare(b.name));
  // Every region refused: that is a permission problem, not a quiet account.
  if (!regions.length && refusal) for (const k of AWS_SOURCE_KEYS) if (AWS_SOURCES[k].regional) client.note(k, false, refusal);

  onProgress({ phase: "Reading CloudFront and Route 53" });
  const [distributions, hostedZones, ec2Prefixes] = await Promise.all([
    client.read("cloudfront", () => readDistributions(client)),
    client.read("route53", () => readZones(client)),
    client.read("ipRanges", fetchEc2Prefixes),
  ]);

  return {
    accountId,
    accountName,
    now: Date.now(),
    unreadable: [...client.coverage.values()].filter((c) => !c.ok).map((c) => c.key),
    rootKey,
    root,
    passwordPolicy,
    users,
    admins: details?.admins ?? null,
    roles: details?.roles ?? null,
    policies: details?.policies ?? null,
    s3Block,
    buckets,
    regions,
    skippedRegions: skippedRegions.sort(),
    distributions,
    hostedZones,
    released: [],
    ec2Prefixes,
  };
}

// ---- paging

/** Follows a paged read: `next` picks the token out of each page, and `fetch` asks for the page after it. */
async function pages<T>(fetch: (token: string | null) => Promise<T>, next: (page: T) => string | null): Promise<T[]> {
  const out: T[] = [];
  let token: string | null = null;
  do {
    const page = await fetch(token);
    out.push(page);
    token = next(page);
  } while (token && out.length < MAX_PAGES);
  return out;
}

/** Every element of a list across the pages of a Query API action. `token` names the paging parameter and the element that carries it. */
async function queryAll(
  client: AwsClient,
  service: string,
  region: string,
  action: string,
  list: string,
  token: { param: string; element: string },
  params: Record<string, string> = {},
): Promise<XmlNode[]> {
  const docs = await pages(
    (t) => client.query(service, region, action, t ? { ...params, [token.param]: t } : params),
    (d) => text(find(d, token.element)),
  );
  return docs.flatMap((d) => items(find(d, list)));
}

const IAM_PAGE = { param: "Marker", element: "Marker" };
const EC2_PAGE = { param: "NextToken", element: "nextToken" };

// ---- IAM

function toRoot(doc: XmlNode): AwsInventory["root"] {
  const map = new Map(items(find(doc, "SummaryMap")).map((e) => [text(e, "key") ?? "", Number(text(e, "value") ?? 0)]));
  return { mfa: map.get("AccountMFAEnabled") === 1, accessKeys: (map.get("AccountAccessKeysPresent") ?? 0) > 0, users: map.get("Users") ?? 0 };
}

function toPasswordPolicy(doc: XmlNode): NonNullable<AwsInventory["passwordPolicy"]> {
  const p = find(doc, "PasswordPolicy");
  const reuse = Number(text(p, "PasswordReusePrevention"));
  return {
    minLength: Number(text(p, "MinimumPasswordLength") ?? 0),
    symbols: bool(p, "RequireSymbols") === true,
    numbers: bool(p, "RequireNumbers") === true,
    uppercase: bool(p, "RequireUppercaseCharacters") === true,
    lowercase: bool(p, "RequireLowercaseCharacters") === true,
    reusePrevention: Number.isFinite(reuse) && reuse > 0 ? reuse : null,
  };
}

async function readUsers(client: AwsClient): Promise<AwsUser[] | null> {
  const list = await client.read("iamUsers", () => queryAll(client, "iam", HOME_REGION, "ListUsers", "Users", IAM_PAGE, { MaxItems: "200" }));
  if (!list) return null;
  const users: AwsUser[] = [];
  await pool(list.slice(0, MAX_USERS), ITEM_CONCURRENCY, async (u) => {
    const name = text(u, "UserName") ?? "";
    const user: AwsUser = { name, createdAt: time(u, "CreateDate"), console: null, passwordLastUsedAt: time(u, "PasswordLastUsed"), mfa: null, keys: null };
    users.push(user);
    try {
      const [keys, mfa, login] = await Promise.all([
        client.query("iam", HOME_REGION, "ListAccessKeys", { UserName: name }),
        client.query("iam", HOME_REGION, "ListMFADevices", { UserName: name }),
        client.optional(() => client.query("iam", HOME_REGION, "GetLoginProfile", { UserName: name })),
      ]);
      user.mfa = items(find(mfa, "MFADevices")).length > 0;
      user.console = !!login;
      user.keys = await Promise.all(
        items(find(keys, "AccessKeyMetadata")).map(async (k) => {
          const id = text(k, "AccessKeyId") ?? "";
          const used = await client.query("iam", HOME_REGION, "GetAccessKeyLastUsed", { AccessKeyId: id });
          return {
            hint: id.slice(-4),
            active: text(k, "Status") === "Active",
            createdAt: time(k, "CreateDate"),
            lastUsedAt: time(find(used, "AccessKeyLastUsed"), "LastUsedDate"),
          };
        }),
      );
    } catch (e) {
      client.note("iamUsers", false, e);
    }
  });
  return users.sort((a, b) => a.name.localeCompare(b.name));
}

interface Statement {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
  Principal?: string | Record<string, string | string[]>;
  Condition?: unknown;
}

const list = <T>(v: T | T[] | undefined): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

/** A policy document as IAM returns it: URL-encoded JSON. Only its statements are looked at, and none of it is stored. */
function statements(encoded: string | null): Statement[] {
  if (!encoded) return [];
  try {
    return list(JSON.parse(decodeURIComponent(encoded)).Statement as Statement | Statement[]);
  } catch {
    return [];
  }
}

/** Allows every action on every resource, without a condition. */
export const grantsEverything = (st: Statement[]): boolean =>
  st.some((s) => s.Effect === "Allow" && !s.Condition && list(s.Action).some((a) => a === "*" || a === "*:*") && list(s.Resource).includes("*"));

/** Who a trust policy lets assume the role. */
export function trustOf(st: Statement[]): AwsTrust[] {
  const out: AwsTrust[] = [];
  for (const s of st) {
    if (s.Effect !== "Allow") continue;
    const conditional = !!s.Condition && Object.keys(s.Condition as object).length > 0;
    if (s.Principal === "*") out.push({ principal: "*", kind: "anyone", conditional });
    else if (s.Principal && typeof s.Principal === "object") {
      for (const p of list(s.Principal.AWS))
        out.push(p === "*" ? { principal: "*", kind: "anyone", conditional } : { principal: p, kind: "account", conditional });
      for (const p of list(s.Principal.Service)) out.push({ principal: p, kind: "service", conditional });
      for (const p of list(s.Principal.Federated)) out.push({ principal: p, kind: "federated", conditional });
    }
  }
  return out;
}

async function readDetails(client: AwsClient): Promise<{ admins: AwsAdmin[]; roles: AwsRole[]; policies: AwsPolicy[] }> {
  const docs = await pages(
    (t) =>
      client.query("iam", HOME_REGION, "GetAccountAuthorizationDetails", {
        MaxItems: "200",
        "Filter.member.1": "User",
        "Filter.member.2": "Group",
        "Filter.member.3": "Role",
        "Filter.member.4": "LocalManagedPolicy",
        ...(t ? { Marker: t } : {}),
      }),
    (d) => text(find(d, "Marker")),
  );
  const all = (name: string) => docs.flatMap((d) => items(find(d, name)));

  const adminArns = new Set<string>();
  const policies: AwsPolicy[] = all("Policies").map((p) => {
    const current = items(p, "PolicyVersionList").find((v) => bool(v, "IsDefaultVersion"));
    const fullAdmin = grantsEverything(statements(text(current, "Document")));
    if (fullAdmin) adminArns.add(text(p, "Arn") ?? "");
    return { name: text(p, "PolicyName") ?? "", fullAdmin, attachments: Number(text(p, "AttachmentCount") ?? 0) };
  });
  /** How a user, group or role holds administrator access, or null. */
  const adminVia = (node: XmlNode, inline: string): string | null => {
    const attached = items(node, "AttachedManagedPolicies").find(
      (a) => ADMIN_POLICY.test(text(a, "PolicyArn") ?? "") || adminArns.has(text(a, "PolicyArn") ?? ""),
    );
    if (attached) return `the ${text(attached, "PolicyName")} policy`;
    const own = items(node, inline).find((i) => grantsEverything(statements(text(i, "PolicyDocument"))));
    return own ? `the inline policy ${text(own, "PolicyName")}` : null;
  };
  const adminGroups = new Map(all("GroupDetailList").flatMap((g) => (adminVia(g, "GroupPolicyList") ? [[text(g, "GroupName") ?? "", true] as const] : [])));

  const admins: AwsAdmin[] = all("UserDetailList").flatMap((u) => {
    const group = items(u, "GroupList").find((g) => adminGroups.has(g.text.trim()));
    const via = adminVia(u, "UserPolicyList") ?? (group ? `the group ${group.text.trim()}` : null);
    return via ? [{ user: text(u, "UserName") ?? "", via }] : [];
  });
  const roles: AwsRole[] = all("RoleDetailList").map((r) => ({
    name: text(r, "RoleName") ?? "",
    trust: trustOf(statements(text(r, "AssumeRolePolicyDocument"))),
    admin: !!adminVia(r, "RolePolicyList"),
    serviceLinked: (text(r, "Path") ?? "").startsWith("/aws-service-role/"),
    profiles: items(r, "InstanceProfileList").flatMap((p) => text(p, "InstanceProfileName") ?? []),
    lastUsedAt: time(r, "RoleLastUsed", "LastUsedDate"),
  }));
  return { admins, roles, policies };
}

// ---- S3

function toBlock(doc: XmlNode): PublicAccessBlock {
  const b = find(doc, "PublicAccessBlockConfiguration");
  return {
    blockPublicAcls: bool(b, "BlockPublicAcls") === true,
    ignorePublicAcls: bool(b, "IgnorePublicAcls") === true,
    blockPublicPolicy: bool(b, "BlockPublicPolicy") === true,
    restrictPublicBuckets: bool(b, "RestrictPublicBuckets") === true,
  };
}

const ACL_GROUP: Record<string, string> = { AllUsers: "everyone", AuthenticatedUsers: "any AWS account" };

async function readBuckets(client: AwsClient): Promise<AwsBucket[] | null> {
  const listed = await client.read("s3Buckets", async () => {
    const doc = await client.s3(HOME_REGION, "/", {});
    return Promise.all(
      items(find(doc, "Buckets"))
        .slice(0, MAX_BUCKETS)
        .map(async (b) => {
          const name = text(b, "Name") ?? "";
          // Older answers don't name the region: ask for it. An empty location is us-east-1, and "EU" is eu-west-1.
          const loc = text(b, "BucketRegion") ?? (await client.s3(HOME_REGION, `/${name}`, { location: "" })).text.trim();
          return { name, region: loc === "EU" ? "eu-west-1" : loc || HOME_REGION };
        }),
    );
  });
  if (!listed) return null;
  const buckets: AwsBucket[] = [];
  let failure: unknown = null;
  let readable = 0;
  await pool(listed, ITEM_CONCURRENCY, async ({ name, region }) => {
    const bucket: AwsBucket = { name, region, block: undefined, policyPublic: undefined, aclPublic: undefined };
    buckets.push(bucket);
    try {
      const sub = (key: string) => client.s3(region, `/${name}`, { [key]: "" });
      const [block, status, acl] = await Promise.all([client.optional(() => sub("publicAccessBlock")), client.optional(() => sub("policyStatus")), sub("acl")]);
      bucket.block = block ? toBlock(block) : null;
      bucket.policyPublic = status ? bool(find(status, "IsPublic")) === true : null;
      bucket.aclPublic = [
        ...new Set(items(find(acl, "AccessControlList")).flatMap((g) => ACL_GROUP[(text(g, "Grantee", "URI") ?? "").split("/").pop() ?? ""] ?? [])),
      ];
      readable++;
    } catch (e) {
      // One bucket can refuse (its own policy, a region the key can't reach) without hiding the others.
      failure ??= e;
    }
  });
  if (listed.length) client.note("s3BucketAccess", readable > 0, failure);
  return buckets.sort((a, b) => a.name.localeCompare(b.name));
}

// ---- regions

const OPEN_CIDRS = new Set(["0.0.0.0/0", "::/0"]);
const port = (v: string | null): number | null => (v == null || !Number.isFinite(Number(v)) ? null : Number(v));

function toSecurityGroup(g: XmlNode): AwsSecurityGroup {
  const open: AwsSecurityGroup["open"] = [];
  for (const p of items(g, "ipPermissions")) {
    const cidrs = [...items(p, "ipRanges").map((r) => text(r, "cidrIp")), ...items(p, "ipv6Ranges").map((r) => text(r, "cidrIpv6"))];
    for (const cidr of cidrs)
      if (cidr && OPEN_CIDRS.has(cidr))
        open.push({ protocol: text(p, "ipProtocol") ?? "-1", from: port(text(p, "fromPort")), to: port(text(p, "toPort")), cidr });
  }
  return { id: text(g, "groupId") ?? "", name: text(g, "groupName") ?? "", vpcId: text(g, "vpcId"), open };
}

function toInstance(i: XmlNode): AwsInstance {
  const meta = at(i, "metadataOptions");
  return {
    id: text(i, "instanceId") ?? "",
    name: text(
      items(i, "tagSet").find((t) => text(t, "key") === "Name"),
      "value",
    ),
    running: text(i, "instanceState", "name") === "running",
    publicIp: text(i, "ipAddress"),
    vpcId: text(i, "vpcId"),
    securityGroups: items(i, "groupSet").flatMap((g) => text(g, "groupId") ?? []),
    imdsV2: text(meta, "httpEndpoint") === "disabled" ? null : text(meta, "httpTokens") === "required",
    // "arn:aws:iam::<account>:instance-profile/<path>/<name>"
    profile: (text(i, "iamInstanceProfile", "arn") ?? "").split("/").pop() || null,
    userDataSecret: undefined,
  };
}

function toInterface(n: XmlNode): AwsInterface {
  const instance = text(n, "attachment", "instanceId");
  const type = text(n, "interfaceType") ?? "interface";
  const description = text(n, "description") ?? "";
  const kind = instance
    ? "instance"
    : type === "network_load_balancer" || description.startsWith("ELB ")
      ? "load balancer"
      : description.startsWith("RDSNetworkInterface")
        ? "database"
        : type === "nat_gateway"
          ? "NAT gateway"
          : type === "lambda" || description.startsWith("AWS Lambda")
            ? "Lambda"
            : type.replace(/_/g, " ");
  return {
    id: text(n, "networkInterfaceId") ?? "",
    publicIp: text(n, "association", "publicIp"),
    securityGroups: items(n, "groupSet").flatMap((g) => text(g, "groupId") ?? []),
    kind,
    owner: instance ?? (description || null),
  };
}

/**
 * The kind of credential written into an instance's start-up script, or null. The script arrives
 * base64-encoded (sometimes gzipped) and is dropped as soon as it has been scanned.
 */
export function secretInUserData(encoded: string | null): string | null {
  if (!encoded) return null;
  try {
    let raw = Buffer.from(encoded, "base64");
    if (raw[0] === 0x1f && raw[1] === 0x8b) raw = gunzipSync(raw);
    return secretKindIn(raw.toString("utf8"));
  } catch {
    return null;
  }
}

function toDatabase(d: XmlNode): AwsDatabase {
  return {
    id: text(d, "DBInstanceIdentifier") ?? "",
    engine: text(d, "Engine") ?? "",
    public: bool(d, "PubliclyAccessible") === true,
    encrypted: bool(d, "StorageEncrypted") === true,
    backupDays: Number(text(d, "BackupRetentionPeriod") ?? 0),
    replica: !!text(d, "ReadReplicaSourceDBInstanceIdentifier") || !!text(d, "ReadReplicaSourceDBClusterIdentifier"),
    vpcId: text(d, "DBSubnetGroup", "VpcId"),
    securityGroups: items(d, "VpcSecurityGroups").flatMap((g) => text(g, "VpcSecurityGroupId") ?? []),
    port: port(text(d, "Endpoint", "Port")),
  };
}

/**
 * Everything read in one region. The first request decides whether the region is open to the access key:
 * if it is refused, the region is skipped (the caller records it) instead of failing every regional source.
 */
async function readRegion(client: AwsClient, region: string): Promise<AwsRegion> {
  const ec2 = (action: string, listName: string, params: Record<string, string> = {}) => queryAll(client, "ec2", region, action, listName, EC2_PAGE, params);
  let vpcNodes: XmlNode[];
  try {
    vpcNodes = await ec2("DescribeVpcs", "vpcSet");
  } catch (e) {
    if (e instanceof AwsError && e.denied) throw e;
    client.note("vpcs", false, e);
    vpcNodes = [];
  }

  const [flowLogs, groups, reservations, ebs, databases, loadBalancers, functions, guardDuty, network, apiDomains] = await Promise.all([
    client.read("vpcs", () => ec2("DescribeFlowLogs", "flowLogSet")),
    client.read("securityGroups", () => ec2("DescribeSecurityGroups", "securityGroupInfo", { MaxResults: "1000" })),
    client.read("instances", () => ec2("DescribeInstances", "reservationSet", { MaxResults: "1000" })),
    client.read("ebs", async () => {
      const [enc, snaps, images] = await Promise.all([
        client.query("ec2", region, "GetEbsEncryptionByDefault"),
        ec2("DescribeSnapshots", "snapshotSet", { "Owner.1": "self", "RestorableBy.1": "all" }),
        ec2("DescribeImages", "imagesSet", { "Owner.1": "self", "ExecutableBy.1": "all" }),
      ]);
      return {
        encryption: bool(find(enc, "ebsEncryptionByDefault")),
        snapshots: snaps.flatMap((s) => text(s, "snapshotId") ?? []),
        images: images.map((i) => ({ id: text(i, "imageId") ?? "", name: text(i, "name") })),
      };
    }),
    client.read("databases", async () =>
      (await queryAll(client, "rds", region, "DescribeDBInstances", "DBInstances", { param: "Marker", element: "Marker" }, { MaxRecords: "100" })).map(
        toDatabase,
      ),
    ),
    client.read("loadBalancers", () => readLoadBalancers(client, region)),
    client.read("functions", () => readFunctions(client, region)),
    client.read("guardduty", async () => {
      const ids: string[] = (await client.json("guardduty", region, "/detector"))?.detectorIds ?? [];
      const detectors = await Promise.all(ids.map((id) => client.json("guardduty", region, `/detector/${id}`)));
      return detectors.some((d) => d?.status === "ENABLED");
    }),
    client.read("networkInterfaces", async () => {
      const [interfaces, addresses] = await Promise.all([
        ec2("DescribeNetworkInterfaces", "networkInterfaceSet", { MaxResults: "1000" }),
        ec2("DescribeAddresses", "addressesSet"),
      ]);
      return { interfaces: interfaces.map(toInterface), addresses: addresses.flatMap((a) => text(a, "publicIp") ?? []) };
    }),
    client.read("apiDomains", async () => {
      // Edge-optimised custom domains get a CloudFront distribution that AWS owns: it is real, but not in ListDistributions.
      const body = await client.json("apigateway", region, "/domainnames", { limit: "500" });
      const list = body?.item ?? body?._embedded?.item ?? [];
      return (Array.isArray(list) ? list : [list]).flatMap((d: Json) =>
        typeof d?.distributionDomainName === "string" ? d.distributionDomainName.toLowerCase() : [],
      );
    }),
  ]);

  const instances = reservations ? reservations.flatMap((r) => items(r, "instancesSet").map(toInstance)).filter((i) => i.id) : null;
  const running = (instances ?? []).filter((i) => i.running);
  if (running.length && running.length <= MAX_USER_DATA)
    await client.read("userData", () =>
      pool(running, ITEM_CONCURRENCY, async (i) => {
        const doc = await client.query("ec2", region, "DescribeInstanceAttribute", { InstanceId: i.id, Attribute: "userData" });
        i.userDataSecret = secretInUserData(text(find(doc, "userData"), "value"));
      }),
    );

  const logged = flowLogs ? new Set(flowLogs.filter((f) => text(f, "flowLogStatus") === "ACTIVE").flatMap((f) => text(f, "resourceId") ?? [])) : null;
  return {
    name: region,
    securityGroups: groups ? groups.map(toSecurityGroup) : null,
    instances,
    ebsEncryptionByDefault: ebs?.encryption ?? null,
    publicSnapshots: ebs?.snapshots ?? null,
    publicImages: ebs?.images ?? null,
    vpcs: vpcNodes.map((v) => {
      const id = text(v, "vpcId") ?? "";
      return { id, isDefault: bool(v, "isDefault") === true, flowLogs: logged ? logged.has(id) : null };
    }),
    databases,
    loadBalancers,
    functions,
    interfaces: network?.interfaces ?? null,
    addresses: network?.addresses ?? null,
    apiDomains,
    guardDuty,
  };
}

async function readLoadBalancers(client: AwsClient, region: string): Promise<AwsLoadBalancer[]> {
  const elb = "elasticloadbalancing";
  const paged = { param: "Marker", element: "NextMarker" };
  // Classic load balancers live in an older version of the same API, and still serve plenty of hostnames.
  const CLASSIC = { Version: "2012-06-01" };
  const [nodes, classic] = await Promise.all([
    queryAll(client, elb, region, "DescribeLoadBalancers", "LoadBalancers", paged, { PageSize: "400" }),
    queryAll(client, elb, region, "DescribeLoadBalancers", "LoadBalancerDescriptions", paged, { ...CLASSIC, PageSize: "400" }),
  ]);
  const groups = (lb: XmlNode) => items(lb, "SecurityGroups").map((g) => g.text.trim());
  const out: AwsLoadBalancer[] = [];
  await pool(nodes, ITEM_CONCURRENCY, async (lb) => {
    const arn = text(lb, "LoadBalancerArn") ?? "";
    const [listeners, attributes] = await Promise.all([
      queryAll(client, elb, region, "DescribeListeners", "Listeners", paged, { LoadBalancerArn: arn }),
      client.query(elb, region, "DescribeLoadBalancerAttributes", { LoadBalancerArn: arn }),
    ]);
    out.push({
      name: text(lb, "LoadBalancerName") ?? "",
      dnsName: (text(lb, "DNSName") ?? "").toLowerCase(),
      type: text(lb, "Type") ?? "",
      internetFacing: text(lb, "Scheme") === "internet-facing",
      vpcId: text(lb, "VpcId"),
      securityGroups: groups(lb),
      accessLogs: bool(
        items(find(attributes, "Attributes")).find((a) => text(a, "Key") === "access_logs.s3.enabled"),
        "Value",
      ),
      listeners: listeners.map((l) => ({
        port: port(text(l, "Port")),
        protocol: text(l, "Protocol") ?? "",
        sslPolicy: text(l, "SslPolicy"),
        redirects: items(l, "DefaultActions").some((a) => text(a, "Type") === "redirect"),
      })),
    });
  });
  await pool(classic, ITEM_CONCURRENCY, async (lb) => {
    const name = text(lb, "LoadBalancerName") ?? "";
    const attributes = await client.query(elb, region, "DescribeLoadBalancerAttributes", { ...CLASSIC, LoadBalancerName: name });
    out.push({
      name,
      dnsName: (text(lb, "DNSName") ?? "").toLowerCase(),
      type: "classic",
      internetFacing: text(lb, "Scheme") === "internet-facing",
      vpcId: text(lb, "VPCId"),
      securityGroups: groups(lb),
      accessLogs: bool(find(attributes, "AccessLog"), "Enabled"),
      // A classic listener can't redirect, and its TLS policy is a named policy rather than a version: neither is judged.
      listeners: items(lb, "ListenerDescriptions").map((l) => ({
        port: port(text(l, "Listener", "LoadBalancerPort")),
        protocol: text(l, "Listener", "Protocol") ?? "",
        sslPolicy: null,
        redirects: false,
      })),
    });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

async function readFunctions(client: AwsClient, region: string): Promise<AwsFunction[]> {
  const docs = await pages(
    (t) => client.json("lambda", region, "/2015-03-31/functions/", { MaxItems: "50", ...(t ? { Marker: t } : {}) }),
    (d: Json) => (typeof d?.NextMarker === "string" && d.NextMarker ? d.NextMarker : null),
  );
  // Only the name, runtime and role are taken: the payload also carries environment variables, which are dropped here.
  const functions: AwsFunction[] = docs
    .flatMap((d: Json) => (Array.isArray(d?.Functions) ? d.Functions : []))
    .map((f: Json) => ({
      name: String(f.FunctionName ?? ""),
      runtime: typeof f.Runtime === "string" ? f.Runtime : null,
      // "arn:aws:iam::<account>:role/<path>/<name>"
      role: typeof f.Role === "string" ? f.Role.split("/").pop() || null : null,
      urls: null,
    }));
  if (functions.length <= MAX_FUNCTION_URLS)
    await pool(functions, ITEM_CONCURRENCY, async (f) => {
      const body = await client.json("lambda", region, `/2021-10-31/functions/${f.name}/urls`);
      f.urls = (Array.isArray(body?.FunctionUrlConfigs) ? body.FunctionUrlConfigs : []).map((u: Json) => ({ authType: String(u.AuthType ?? "") }));
    });
  return functions.sort((a, b) => a.name.localeCompare(b.name));
}

// ---- CloudFront and Route 53

async function readDistributions(client: AwsClient): Promise<AwsDistribution[]> {
  const docs = await pages(
    (t) => client.xml("cloudfront", HOME_REGION, "cloudfront.amazonaws.com", "/2020-05-31/distribution", { MaxItems: "100", ...(t ? { Marker: t } : {}) }),
    (d) => text(d, "NextMarker"),
  );
  return docs
    .flatMap((d) => items(d, "Items"))
    .map((x) => {
      const cert = at(x, "ViewerCertificate");
      return {
        id: text(x, "Id") ?? "",
        domainName: (text(x, "DomainName") ?? "").toLowerCase(),
        enabled: bool(x, "Enabled") === true,
        aliases: items(x, "Aliases", "Items").map((a) => a.text.trim().toLowerCase()),
        viewerPolicies: [
          ...new Set([
            text(x, "DefaultCacheBehavior", "ViewerProtocolPolicy"),
            ...items(x, "CacheBehaviors", "Items").map((b) => text(b, "ViewerProtocolPolicy")),
          ]),
        ].flatMap((p) => p ?? []),
        minTls: text(cert, "MinimumProtocolVersion"),
        defaultCertificate: bool(cert, "CloudFrontDefaultCertificate") === true,
        waf: !!text(x, "WebACLId"),
        origins: items(x, "Origins", "Items").map((o) => ({
          domain: (text(o, "DomainName") ?? "").toLowerCase(),
          protocolPolicy: text(o, "CustomOriginConfig", "OriginProtocolPolicy"),
          s3: !!at(o, "S3OriginConfig") || /\.s3[.-]/.test(text(o, "DomainName") ?? ""),
          restricted: !!text(o, "OriginAccessControlId") || !!text(o, "S3OriginConfig", "OriginAccessIdentity"),
        })),
      };
    });
}

const RECORD_TYPES = new Set(["A", "AAAA", "CNAME"]);
/** "www.example.com." → "www.example.com"; Route 53 writes "*" as "\052". */
const hostname = (s: string) =>
  s
    .replace(/\\(\d{3})/g, (_, o: string) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\.$/, "")
    .toLowerCase();

async function readZones(client: AwsClient): Promise<AwsHostedZone[]> {
  const r53 = (path: string, query: Record<string, string>) => client.xml("route53", HOME_REGION, "route53.amazonaws.com", path, query);
  const docs = await pages(
    (t) => r53("/2013-04-01/hostedzone", { maxitems: "100", ...(t ? { marker: t } : {}) }),
    (d) => (bool(d, "IsTruncated") ? text(d, "NextMarker") : null),
  );
  const zones: AwsHostedZone[] = docs
    .flatMap((d) => items(d, "HostedZones"))
    .slice(0, MAX_ZONES)
    .map((z) => ({
      id: (text(z, "Id") ?? "").replace(/^\/hostedzone\//, ""),
      name: hostname(text(z, "Name") ?? ""),
      private: bool(z, "Config", "PrivateZone") === true,
      records: null,
    }));
  await pool(zones, REGION_CONCURRENCY, async (z) => {
    // Private zones answer only inside a VPC: nothing on the internet resolves them.
    if (z.private) return void (z.records = []);
    const recordDocs = await pages(
      (t) => r53(`/2013-04-01/hostedzone/${z.id}/rrset`, { maxitems: "300", ...(t ? { name: t.split(" ")[0], type: t.split(" ")[1] } : {}) }),
      (d) => (bool(d, "IsTruncated") && text(d, "NextRecordName") ? `${text(d, "NextRecordName")} ${text(d, "NextRecordType")}` : null),
    );
    z.records = recordDocs
      .flatMap((d) => items(d, "ResourceRecordSets"))
      .filter((r) => RECORD_TYPES.has(text(r, "Type") ?? ""))
      .map((r): AwsRecord => {
        const alias = text(r, "AliasTarget", "DNSName");
        return {
          name: hostname(text(r, "Name") ?? ""),
          type: text(r, "Type") ?? "",
          targets: alias ? [hostname(alias)] : items(r, "ResourceRecords").map((v) => hostname(text(v, "Value") ?? "")),
          alias: !!alias,
        };
      });
  });
  return zones.sort((a, b) => a.name.localeCompare(b.name));
}

async function pool<T>(list: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, list.length) }, async () => {
      while (next < list.length) await fn(list[next++]);
    }),
  );
}

export type { AwsSourceKey };
