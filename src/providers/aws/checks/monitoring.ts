// Detection where it matters: GuardDuty in the regions that run something, flow
// logs on the VPCs that carry traffic, and access logs on the load balancers the
// internet reaches. Empty regions and unused default
// VPCs aren't reported.

import { defineChecks, inUse } from "./define.ts";

export default defineChecks(
  {
    "AMO-001": {
      category: "Monitoring",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
      requires: ["guardduty", "instances", "databases", "loadBalancers", "functions"],
      title: "GuardDuty is off in a region that runs workloads",
      why: "Nothing watches the region for stolen credentials in use, instances talking to known malware hosts, or unusual API calls. A compromise there goes unnoticed until the bill or a customer reveals it.",
      fix: "Open GuardDuty in the region and choose Get started → Enable GuardDuty. With several accounts, enable it for the organization from the delegated administrator account.",
    },
    "AMO-002": {
      category: "Monitoring",
      severity: "low",
      docs: "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
      requires: ["vpcs", "instances", "databases", "loadBalancers"],
      title: "VPC with running resources has no flow logs",
      why: "Without flow logs there is no record of which addresses talked to what. After an incident you can't tell what an attacker reached or what data left.",
      fix: "In the VPC console, select the VPC → Flow logs → Create flow log. Capture rejected traffic at least, and send it to CloudWatch Logs or S3.",
    },
    "AMO-003": {
      category: "Monitoring",
      severity: "low",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html",
      requires: ["loadBalancers"],
      title: "Internet-facing load balancer keeps no access logs",
      why: "The load balancer is where the internet meets your application, and without access logs there is no record of who requested what. After an attack you can't tell which addresses were involved or what they reached.",
      fix: "In EC2 → Load Balancers → the load balancer → Attributes → Edit, turn on Access logs and choose an S3 bucket. Give the bucket a lifecycle rule so old logs expire.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const lb of r.loadBalancers ?? [])
        if (lb.internetFacing && lb.accessLogs != null)
          report("AMO-003", { zone: r.name, resource: lb.name, pass: lb.accessLogs, link: d.loadBalancers(r.name) });
      if (!inUse(r)) continue;
      if (r.guardDuty != null) report("AMO-001", { zone: r.name, resource: r.name, pass: r.guardDuty, link: d.guardDuty(r.name) });

      const busy = new Set([
        ...(r.instances ?? []).filter((i) => i.running).map((i) => i.vpcId),
        ...(r.databases ?? []).map((x) => x.vpcId),
        ...(r.loadBalancers ?? []).map((x) => x.vpcId),
      ]);
      for (const v of r.vpcs ?? []) {
        if (!busy.has(v.id) || v.flowLogs == null) continue;
        report("AMO-002", { zone: r.name, resource: v.isDefault ? `${v.id} (default VPC)` : v.id, pass: v.flowLogs, link: d.vpc(r.name, v.id) });
      }
    }
  },
);
