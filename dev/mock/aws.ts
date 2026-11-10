// A fetch replacement that serves a small, fictional AWS account, so AWS scans run
// end to end without network access (tests and `npm run dev -- --mock`). It chains
// onto whatever fetch is installed, so it works together with the other mocks.
//
// One access key reaches the account "mock-aws": IAM, S3, two regions (eu-west-1
// runs the workloads, us-east-1 is empty), CloudFront and Route 53. As with the
// other mocks, the data is deliberately imperfect so every check family has
// something to find, and dates are relative to now. Answers are XML or JSON in the
// shapes of the AWS API references.

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

export const MOCK_AWS_ACCOUNT = "111122223333";
export const MOCK_AWS_KEY_ID = "AKIAMOCKMOCKMOCK0001";
/** The credential as the Accounts page sends it: key ID and secret, joined. */
export const MOCK_AWS_TOKEN = `${MOCK_AWS_KEY_ID}:mockSecretMockSecretMockSecretMockSecret0`;
/** A value the mock returns in a Lambda environment variable, so the scanner's job of dropping it is tested. */
export const MOCK_AWS_SECRET_VALUE = "mock-lambda-env-value-DO-NOT-STORE";
export const MOCK_AWS_CLOUDFRONT = "d1mockexample.cloudfront.net";

interface MockOptions {
  onRequest?: (url: URL, init?: RequestInit) => void;
  /** Requests (regex on "host/path?query") that answer 403, to simulate a policy that doesn't allow them. */
  deny?: RegExp[];
  /** Extra enabled regions that refuse every request, like a region closed by a service control policy. */
  refuseRegions?: string[];
}

const x = (tag: string, ...children: (string | number | boolean)[]) => `<${tag}>${children.join("")}</${tag}>`;
const doc = (enc: object) => encodeURIComponent(JSON.stringify(enc));
const policy = (name: string) => x("PolicyName", name) + x("PolicyArn", `arn:aws:iam::aws:policy/${name}`);

const WORK = "eu-west-1";
const VPC = "vpc-0a1b2c3d4e5f60001";
const SG = { web: "sg-0web0000000000001", admin: "sg-0admin00000000001", db: "sg-0db00000000000001", legacy: "sg-0legacy0000000001" };

const iam: Record<string, (q: URLSearchParams) => string | null> = {
  ListAccountAliases: () => x("ListAccountAliasesResult", x("AccountAliases", x("member", "mock-aws")), x("IsTruncated", false)),
  GetAccountSummary: () =>
    x(
      "GetAccountSummaryResult",
      x(
        "SummaryMap",
        ...Object.entries({ AccountMFAEnabled: 0, AccountAccessKeysPresent: 1, Users: 3 }).map(([k, v]) => x("entry", x("key", k), x("value", v))),
      ),
    ),
  // The account never set a password policy.
  GetAccountPasswordPolicy: () => null,
  ListUsers: () =>
    x(
      "ListUsersResult",
      x(
        "Users",
        x("member", x("UserName", "alex"), x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/alex`), x("CreateDate", ago(700)), x("PasswordLastUsed", ago(1))),
        x("member", x("UserName", "ci-deploy"), x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/ci-deploy`), x("CreateDate", ago(500))),
        x("member", x("UserName", "sam"), x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/sam`), x("CreateDate", ago(600)), x("PasswordLastUsed", ago(200))),
      ),
      x("IsTruncated", false),
    ),
  ListAccessKeys: (q) => {
    const keys: Record<string, [string, number][]> = { alex: [["AKIAMOCKALEX00000A1B2", 400]], "ci-deploy": [["AKIAMOCKCI0000000C3D4", 200]], sam: [] };
    return x(
      "ListAccessKeysResult",
      x(
        "AccessKeyMetadata",
        ...(keys[q.get("UserName") ?? ""] ?? []).map(([id, age]) => x("member", x("AccessKeyId", id), x("Status", "Active"), x("CreateDate", ago(age)))),
      ),
    );
  },
  GetAccessKeyLastUsed: (q) =>
    x(
      "GetAccessKeyLastUsedResult",
      x("AccessKeyLastUsed", q.get("AccessKeyId")?.endsWith("A1B2") ? x("LastUsedDate", ago(2)) : x("LastUsedDate", ago(150)), x("ServiceName", "s3")),
    ),
  ListMFADevices: (q) => x("ListMFADevicesResult", x("MFADevices", q.get("UserName") === "sam" ? x("member", x("SerialNumber", "mock-device")) : "")),
  // ci-deploy has no console password.
  GetLoginProfile: (q) => (q.get("UserName") === "ci-deploy" ? null : x("GetLoginProfileResult", x("LoginProfile", x("UserName", q.get("UserName") ?? "")))),
  GetAccountAuthorizationDetails: () =>
    x(
      "GetAccountAuthorizationDetailsResult",
      x("IsTruncated", false),
      x(
        "UserDetailList",
        x("member", x("UserName", "alex"), x("GroupList", x("member", "Admins")), x("AttachedManagedPolicies", ""), x("UserPolicyList", "")),
        x("member", x("UserName", "ci-deploy"), x("GroupList", ""), x("AttachedManagedPolicies", x("member", policy("AmazonS3FullAccess")))),
        x("member", x("UserName", "sam"), x("GroupList", ""), x("AttachedManagedPolicies", x("member", policy("ReadOnlyAccess")))),
      ),
      x("GroupDetailList", x("member", x("GroupName", "Admins"), x("AttachedManagedPolicies", x("member", policy("AdministratorAccess"))))),
      x(
        "RoleDetailList",
        x(
          "member",
          x("RoleName", "partner-access"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", x("member", policy("AdministratorAccess"))),
        ),
        x(
          "member",
          x("RoleName", "app-server"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", ""),
        ),
        x(
          "member",
          x("RoleName", "web-admin-role"),
          x("Path", "/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
          x("AttachedManagedPolicies", x("member", policy("AdministratorAccess"))),
          x("InstanceProfileList", x("member", x("InstanceProfileName", "web-admin"))),
        ),
        // A vendor's account, trusted without an external ID, and not used for months.
        x(
          "member",
          x("RoleName", "vendor-monitoring"),
          x("Path", "/"),
          x(
            "AssumeRolePolicyDocument",
            doc({ Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::999988887777:root" }, Action: "sts:AssumeRole" }] }),
          ),
          x("AttachedManagedPolicies", x("member", policy("ReadOnlyAccess"))),
          x("RoleLastUsed", x("LastUsedDate", ago(200))),
        ),
        x(
          "member",
          x("RoleName", "AWSServiceRoleForSupport"),
          x("Path", "/aws-service-role/support.amazonaws.com/"),
          x("AssumeRolePolicyDocument", doc({ Statement: [{ Effect: "Allow", Principal: { Service: "support.amazonaws.com" }, Action: "sts:AssumeRole" }] })),
        ),
      ),
      x(
        "Policies",
        x(
          "member",
          x("PolicyName", "legacy-full-access"),
          x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:policy/legacy-full-access`),
          x("AttachmentCount", 2),
          x(
            "PolicyVersionList",
            x("member", x("Document", doc({ Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] })), x("IsDefaultVersion", true)),
          ),
        ),
      ),
    ),
};

const openRule = (protocol: string, from: number | null, to: number | null, cidr = "0.0.0.0/0") =>
  x("item", x("ipProtocol", protocol), from == null ? "" : x("fromPort", from) + x("toPort", to ?? from), x("ipRanges", x("item", x("cidrIp", cidr))));
const group = (id: string, name: string, vpc: string, ...rules: string[]) =>
  x("item", x("groupId", id), x("groupName", name), x("vpcId", vpc), x("ipPermissions", ...rules));
/** Addresses in the mock's "EC2 range" (TEST-NET-2), which the mock ip-ranges file publishes. */
export const MOCK_AWS_IP = "198.51.100.50";
/** An Elastic IP the account gives up when `mockAws.released` is set, as when an old server is deleted between two scans. */
export const MOCK_AWS_OLD_IP = "198.51.100.99";
export const mockAws = { released: false };
const LB_IP = "198.51.100.60";
const DB_IP = "198.51.100.70";
const WEB = "i-0web00000000000001";

const instance = (id: string, name: string, o: { ip?: string; sg: string[]; tokens: string; profile?: string }) =>
  x(
    "item",
    x(
      "instancesSet",
      x(
        "item",
        x("instanceId", id),
        x("instanceState", x("name", "running")),
        x("vpcId", VPC),
        o.ip ? x("ipAddress", o.ip) : "",
        x("groupSet", ...o.sg.map((g) => x("item", x("groupId", g)))),
        o.profile ? x("iamInstanceProfile", x("arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:instance-profile/${o.profile}`)) : "",
        x("metadataOptions", x("httpTokens", o.tokens), x("httpEndpoint", "enabled")),
        x("tagSet", x("item", x("key", "Name"), x("value", name))),
      ),
    ),
  );

const eni = (id: string, groups: string[], o: { ip?: string; instance?: string; description?: string }) =>
  x(
    "item",
    x("networkInterfaceId", id),
    x("description", o.description ?? ""),
    x("interfaceType", "interface"),
    x("groupSet", ...groups.map((g) => x("item", x("groupId", g)))),
    o.ip ? x("association", x("publicIp", o.ip)) : "",
    o.instance ? x("attachment", x("instanceId", o.instance)) : "",
  );

/** The web instance's start-up script exports a credential; the mock returns it so the scanner's job of not keeping it is tested. */
export const MOCK_AWS_USER_DATA_KEY = "AKIAMOCKUSERDATA0001";
const USER_DATA = Buffer.from(`#!/bin/bash\nexport AWS_ACCESS_KEY_ID=${MOCK_AWS_USER_DATA_KEY}\nsystemctl start web\n`).toString("base64");

const ec2: Record<string, (region: string) => string> = {
  DescribeVpcs: (r) =>
    x("vpcSet", r === WORK ? x("item", x("vpcId", VPC), x("isDefault", false)) : x("item", x("vpcId", "vpc-0default000000001"), x("isDefault", true))),
  DescribeFlowLogs: () => x("flowLogSet", ""),
  DescribeSecurityGroups: (r) =>
    x(
      "securityGroupInfo",
      ...(r === WORK
        ? [
            group(SG.web, "web", VPC, openRule("tcp", 443, 443)),
            group(SG.admin, "admin-access", VPC, openRule("tcp", 22, 22)),
            group(SG.db, "database", VPC, openRule("tcp", 5432, 5432)),
            group(SG.legacy, "legacy-open", VPC, openRule("-1", null, null)),
          ]
        : [group("sg-0default000000001", "default", "vpc-0default000000001")]),
    ),
  DescribeInstances: (r) =>
    x(
      "reservationSet",
      ...(r === WORK
        ? [
            // Public, reachable on SSH and HTTPS, IMDSv1 allowed, and running as an administrator.
            instance(WEB, "web-1", { ip: MOCK_AWS_IP, sg: [SG.admin, SG.web], tokens: "optional", profile: "web-admin" }),
            instance("i-0worker0000000001", "worker-1", { sg: [SG.web], tokens: "required" }),
          ]
        : []),
    ),
  // What each group is attached to: the web instance, the load balancer and the database have public addresses.
  DescribeNetworkInterfaces: (r) =>
    x(
      "networkInterfaceSet",
      ...(r === WORK
        ? [
            eni("eni-0web0000000000001", [SG.admin, SG.web], { ip: MOCK_AWS_IP, instance: WEB }),
            eni("eni-0worker00000000001", [SG.web], { instance: "i-0worker0000000001" }),
            eni("eni-0alb0000000000001", [SG.web], { ip: LB_IP, description: "ELB app/web-alb/0001" }),
            eni("eni-0rds0000000000001", [SG.db], { ip: DB_IP, description: "RDSNetworkInterface" }),
          ]
        : []),
    ),
  // The second Elastic IP is there until `mockAws.released` is set: then DNS that points at it is left dangling.
  DescribeAddresses: (r) =>
    x(
      "addressesSet",
      r === WORK
        ? x("item", x("publicIp", MOCK_AWS_IP), x("allocationId", "eipalloc-0mock0001")) +
            (mockAws.released ? "" : x("item", x("publicIp", MOCK_AWS_OLD_IP), x("allocationId", "eipalloc-0mock0002")))
        : "",
    ),
  GetEbsEncryptionByDefault: () => x("ebsEncryptionByDefault", false),
  DescribeSnapshots: (r) => x("snapshotSet", r === WORK ? x("item", x("snapshotId", "snap-0mock0000000001")) : ""),
  DescribeImages: (r) => x("imagesSet", r === WORK ? x("item", x("imageId", "ami-0mock00000000001"), x("name", "legacy-base")) : ""),
};

const ELB_DNS = `web-alb-1234567890.${WORK}.elb.amazonaws.com`;
const CLASSIC_DNS = `internal-legacy-elb-123456789.${WORK}.elb.amazonaws.com`;
export const MOCK_AWS_API_DOMAIN = "d5apigwmockexample.cloudfront.net";
export const MOCK_AWS_ELB = ELB_DNS;
const ELB_ARN = `arn:aws:elasticloadbalancing:${WORK}:${MOCK_AWS_ACCOUNT}:loadbalancer/app/web-alb/0001`;
const listener = (port: number, protocol: string, extra = "") =>
  x("member", x("Port", port), x("Protocol", protocol), extra, x("DefaultActions", x("member", x("Type", "forward"))));

const BUCKETS: Record<string, { region: string; block: boolean; public: boolean }> = {
  "mock-backups": { region: "us-east-1", block: true, public: false },
  "mock-logs": { region: WORK, block: false, public: false },
  "mock-public-assets": { region: WORK, block: false, public: true },
};
const blockXml = () =>
  x("PublicAccessBlockConfiguration", ...["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"].map((k) => x(k, true)));

function s3(path: string, q: URLSearchParams): string | null {
  if (path === "/")
    return x("ListAllMyBucketsResult", x("Buckets", ...Object.entries(BUCKETS).map(([n, b]) => x("Bucket", x("Name", n), x("BucketRegion", b.region)))));
  const b = BUCKETS[path.slice(1)];
  if (!b) return null;
  if (q.has("publicAccessBlock")) return b.block ? blockXml() : null;
  if (q.has("policyStatus")) return b.public ? x("PolicyStatus", x("IsPublic", "TRUE")) : null;
  if (q.has("acl")) return x("AccessControlPolicy", x("AccessControlList", x("Grant", x("Grantee", x("ID", "owner")), x("Permission", "FULL_CONTROL"))));
  return null;
}

const cloudfront = () =>
  x(
    "DistributionList",
    x("IsTruncated", false),
    x(
      "Items",
      x(
        "DistributionSummary",
        x("Id", "E1MOCKDIST00001"),
        x("DomainName", MOCK_AWS_CLOUDFRONT),
        x("Enabled", true),
        x("Aliases", x("Quantity", 1), x("Items", x("CNAME", "cdn.mock.example"))),
        x("Origins", x("Items", x("Origin", x("DomainName", "origin.mock.example"), x("CustomOriginConfig", x("OriginProtocolPolicy", "http-only"))))),
        x("DefaultCacheBehavior", x("ViewerProtocolPolicy", "allow-all")),
        x("CacheBehaviors", x("Quantity", 0)),
        x("ViewerCertificate", x("CloudFrontDefaultCertificate", false), x("MinimumProtocolVersion", "TLSv1_2016")),
        x("WebACLId", ""),
      ),
    ),
  );

const ZONE = "Z0MOCKZONE000001";
const record = (name: string, type: string, target: string, alias = false) =>
  x(
    "ResourceRecordSet",
    x("Name", `${name}.`),
    x("Type", type),
    alias ? x("AliasTarget", x("DNSName", `${target}.`)) : x("ResourceRecords", x("ResourceRecord", x("Value", target))),
  );
function route53(path: string): string | null {
  if (path === "/2013-04-01/hostedzone")
    return x(
      "ListHostedZonesResponse",
      x("HostedZones", x("HostedZone", x("Id", `/hostedzone/${ZONE}`), x("Name", "mock-aws.example."), x("Config", x("PrivateZone", false)))),
      x("IsTruncated", false),
    );
  if (path === `/2013-04-01/hostedzone/${ZONE}/rrset`)
    return x(
      "ListResourceRecordSetsResponse",
      x(
        "ResourceRecordSets",
        record("www.mock-aws.example", "A", MOCK_AWS_CLOUDFRONT, true),
        record("api.mock-aws.example", "A", `dualstack.${ELB_DNS}`, true),
        // The distribution and the bucket behind these two are gone.
        record("old-shop.mock-aws.example", "CNAME", "d9gonemockexample.cloudfront.net"),
        record("static.mock-aws.example", "A", `s3-website-${WORK}.amazonaws.com`, true),
        // A classic load balancer, an API Gateway domain and the web instance's address: all still there.
        record("legacy.mock-aws.example", "CNAME", CLASSIC_DNS),
        record("gateway.mock-aws.example", "CNAME", MOCK_AWS_API_DOMAIN),
        record("vm.mock-aws.example", "A", MOCK_AWS_IP),
        // The Elastic IP the account gives up (see mockAws.released), an address that was never the account's,
        // and a load balancer that was deleted.
        record("old-vm.mock-aws.example", "A", MOCK_AWS_OLD_IP),
        record("partner.mock-aws.example", "A", "198.51.100.200"),
        record("gone-lb.mock-aws.example", "CNAME", `gone-lb-987654321.${WORK}.elb.amazonaws.com`),
        // No Vercel project serves this one.
        record("docs.mock-aws.example", "CNAME", "cname.vercel-dns.com"),
      ),
      x("IsTruncated", false),
    );
  return null;
}

function lambda(path: string, region: string): unknown {
  if (region !== WORK) return path.endsWith("/urls") ? { FunctionUrlConfigs: [] } : { Functions: [] };
  if (path === "/2015-03-31/functions/")
    return {
      Functions: [
        {
          FunctionName: "thumbnailer",
          Runtime: "nodejs16.x",
          Role: `arn:aws:iam::${MOCK_AWS_ACCOUNT}:role/web-admin-role`,
          Environment: { Variables: { UPLOAD_API_KEY: MOCK_AWS_SECRET_VALUE } },
        },
        { FunctionName: "billing-export", Runtime: "python3.13" },
      ],
    };
  const name = /^\/2021-10-31\/functions\/([^/]+)\/urls$/.exec(path)?.[1];
  return name ? { FunctionUrlConfigs: [{ AuthType: name === "thumbnailer" ? "NONE" : "AWS_IAM" }] } : null;
}

export function installMockAws(o: MockOptions = {}): () => void {
  const real = globalThis.fetch;
  const regions = ["us-east-1", WORK, ...(o.refuseRegions ?? [])];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (!url.hostname.endsWith(".amazonaws.com")) return real(input as string, init);
    o.onRequest?.(url, init);
    const xml = (body: string, status = 200) => new Response(`<?xml version="1.0"?>${body}`, { status, headers: { "content-type": "text/xml" } });
    const fail = (status: number, code: string, message: string) => xml(x("ErrorResponse", x("Error", x("Code", code), x("Message", message))), status);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    const missing = () => fail(404, "NoSuchEntity", "Not found");

    // AWS's published address ranges: a public file, read without a credential.
    if (url.hostname === "ip-ranges.amazonaws.com")
      return json({
        prefixes: [
          { ip_prefix: "198.51.100.0/24", region: WORK, service: "AMAZON" },
          { ip_prefix: "198.51.100.0/24", region: WORK, service: "EC2" },
        ],
      });
    const auth = String(new Headers(init?.headers).get("authorization") ?? "");
    if (!auth.includes(`Credential=${MOCK_AWS_KEY_ID}/`)) return fail(403, "InvalidClientTokenId", "The security token included in the request is invalid.");
    const [service, second] = url.hostname.split(".");
    const region = /^[a-z]{2}-[a-z]+-\d$/.test(second) ? second : "us-east-1";
    const q = url.searchParams;
    const action = q.get("Action") ?? "";
    if (o.deny?.some((re) => re.test(`${url.hostname}${url.pathname}${url.search}`)) || o.refuseRegions?.includes(region))
      return fail(403, "UnauthorizedOperation", "You are not authorized to perform this operation.");

    if (service === "sts")
      return xml(
        x(
          "GetCallerIdentityResponse",
          x("GetCallerIdentityResult", x("Arn", `arn:aws:iam::${MOCK_AWS_ACCOUNT}:user/edgewatch`), x("Account", MOCK_AWS_ACCOUNT)),
        ),
      );
    if (service === "iam") {
      const body = iam[action]?.(q);
      return body ? xml(x(`${action}Response`, body)) : missing();
    }
    if (service === "ec2") {
      if (action === "DescribeRegions") return xml(x("DescribeRegionsResponse", x("regionInfo", ...regions.map((r) => x("item", x("regionName", r))))));
      if (action === "DescribeInstanceAttribute")
        return xml(
          x(
            "DescribeInstanceAttributeResponse",
            x("instanceId", q.get("InstanceId") ?? ""),
            x("userData", q.get("InstanceId") === WEB ? x("value", USER_DATA) : ""),
          ),
        );
      const body = ec2[action]?.(region);
      return body ? xml(x(`${action}Response`, body)) : missing();
    }
    if (service === "rds")
      return xml(
        x(
          "DescribeDBInstancesResponse",
          x(
            "DescribeDBInstancesResult",
            x(
              "DBInstances",
              region === WORK
                ? x(
                    "DBInstance",
                    x("DBInstanceIdentifier", "orders-db"),
                    x("Engine", "postgres"),
                    x("PubliclyAccessible", true),
                    x("StorageEncrypted", false),
                    x("BackupRetentionPeriod", 0),
                    x("DBSubnetGroup", x("VpcId", VPC)),
                    x("VpcSecurityGroups", x("VpcSecurityGroupMembership", x("VpcSecurityGroupId", SG.db))),
                    x("Endpoint", x("Port", 5432)),
                  )
                : "",
            ),
          ),
        ),
      );
    if (service === "elasticloadbalancing") {
      // The older API version lists classic load balancers: one, which a Route 53 record still uses.
      if (q.get("Version") === "2012-06-01") {
        if (action === "DescribeLoadBalancerAttributes")
          return xml(x("DescribeLoadBalancerAttributesResponse", x("LoadBalancerAttributes", x("AccessLog", x("Enabled", true)))));
        const classic = x(
          "member",
          x("LoadBalancerName", "legacy-elb"),
          x("DNSName", CLASSIC_DNS),
          x("Scheme", "internal"),
          x("VPCId", VPC),
          x("SecurityGroups", x("member", SG.web)),
          x("ListenerDescriptions", x("member", x("Listener", x("Protocol", "TCP"), x("LoadBalancerPort", 8443)))),
        );
        return xml(x("DescribeLoadBalancersResponse", x("LoadBalancerDescriptions", region === WORK ? classic : "")));
      }
      if (action === "DescribeLoadBalancerAttributes")
        return xml(x("DescribeLoadBalancerAttributesResponse", x("Attributes", x("member", x("Key", "access_logs.s3.enabled"), x("Value", false)))));
      if (action === "DescribeListeners")
        return xml(x("DescribeListenersResponse", x("Listeners", listener(80, "HTTP"), listener(443, "HTTPS", x("SslPolicy", "ELBSecurityPolicy-2016-08")))));
      const lb = x(
        "member",
        x("LoadBalancerArn", ELB_ARN),
        x("LoadBalancerName", "web-alb"),
        x("DNSName", ELB_DNS),
        x("Scheme", "internet-facing"),
        x("Type", "application"),
        x("VpcId", VPC),
        x("SecurityGroups", x("member", SG.web)),
      );
      return xml(x("DescribeLoadBalancersResponse", x("LoadBalancers", region === WORK ? lb : "")));
    }
    if (service === "guardduty") return json({ detectorIds: [] });
    // An edge-optimised custom domain: its CloudFront distribution belongs to AWS, not to the account.
    if (service === "apigateway")
      return json({ item: region === WORK ? [{ domainName: "gateway.mock-aws.example", distributionDomainName: MOCK_AWS_API_DOMAIN }] : [] });
    if (service === "lambda") {
      const body = lambda(url.pathname, region);
      return body ? json(body) : json({ Message: "Not found" }, 404);
    }
    if (service === "cloudfront") return xml(cloudfront());
    if (service === "route53") {
      const body = route53(url.pathname);
      return body ? xml(body) : missing();
    }
    // S3's account-level API is addressed as <account>.s3-control.<region>; this account never set its block.
    if (second === "s3-control") return fail(404, "NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found");
    if (service === "s3") {
      const body = s3(url.pathname, q);
      return body ? xml(body) : fail(404, "NoSuchConfiguration", "Not found");
    }
    return fail(404, "UnknownOperation", `No mock for ${url.hostname}${url.pathname}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}
