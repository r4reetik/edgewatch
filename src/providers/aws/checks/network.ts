// Security groups that let the whole internet in: on every port, on SSH and RDP,
// or on database ports. What matters is what the group is attached to, so each
// finding is judged by the network interfaces that use it: a group on something
// with a public address is a way in today, one on private interfaces needs
// another mistake first, and one attached to nothing is waiting for its first use.

import { defineChecks, ruleText, usedBy } from "./define.ts";
import type { AwsInterface, AwsRegion, AwsSecurityGroup } from "../types.ts";
import type { Severity } from "../../../core/types.ts";

const ADMIN_PORTS: Record<number, string> = { 22: "SSH", 3389: "RDP" };
export const DATABASE_PORTS: Record<number, string> = {
  1433: "SQL Server",
  1521: "Oracle",
  3306: "MySQL",
  5432: "PostgreSQL",
  5439: "Redshift",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
};

type Rule = AwsSecurityGroup["open"][number];
const isAll = (r: Rule) => r.protocol === "-1";
const covers = (r: Rule, port: number) => (r.protocol === "tcp" || r.protocol === "6") && r.from != null && r.to != null && r.from <= port && port <= r.to;
/** The open rules of a group that reach any of the ports, with the service each one exposes. All-traffic rules have their own check. */
const exposed = (g: AwsSecurityGroup, ports: Record<number, string>) =>
  g.open.filter((r) => !isAll(r)).flatMap((r) => Object.entries(ports).flatMap(([p, name]) => (covers(r, Number(p)) ? [{ rule: r, name }] : [])));

/** "web-1 (instance)" or "load balancer app/web/…": what a network interface belongs to. */
function ownerText(region: AwsRegion, i: AwsInterface): string {
  if (i.kind !== "instance") return i.owner ? `${i.kind} ${i.owner}`.slice(0, 80) : i.kind;
  const inst = region.instances?.find((x) => x.id === i.owner);
  return inst?.name ? `${inst.name} (${inst.id})` : (i.owner ?? "instance");
}

const ONE_LOWER: Record<string, Severity> = { critical: "high", high: "medium", medium: "low", low: "low" };

export default defineChecks(
  {
    "ANW-001": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
      requires: ["securityGroups", "networkInterfaces"],
      attackPath: true,
      title: "Security group opens SSH or RDP to the internet",
      why: "Remote administration ports are scanned and brute-forced around the clock. An exposed SSH or RDP port turns one weak password or unpatched service into a foothold.",
      fix: "1. Edit the group's inbound rules and replace 0.0.0.0/0 with your office or VPN range. 2. Better: remove the rule and connect with Session Manager or EC2 Instance Connect Endpoint, which need no inbound port. 3. If nothing uses the group, delete it.",
    },
    "ANW-002": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
      requires: ["securityGroups", "networkInterfaces"],
      title: "Security group opens a database port to the internet",
      why: "A database reachable from the internet is protected by its password alone, and exposed to every bug in its network protocol.",
      fix: "Edit the group's inbound rules so the database port is allowed only from the security group of the application that uses it, not from 0.0.0.0/0. If nothing uses the group, delete it.",
    },
    "ANW-003": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
      requires: ["securityGroups", "networkInterfaces"],
      attackPath: true,
      title: "Security group allows all traffic from the internet",
      why: "Every port of everything that uses this group is reachable by anyone: admin interfaces, databases, debug ports and services nobody remembers are listening.",
      fix: "Edit the group's inbound rules: delete the rule that allows all traffic from 0.0.0.0/0 or ::/0, and add rules for the specific ports the service needs. If nothing uses the group, delete it.",
    },
  },
  ({ inv, d }, report) => {
    for (const region of inv.regions) {
      if (!region.securityGroups || !region.interfaces) continue;
      for (const g of region.securityGroups) {
        const attached = usedBy(region, g.id);
        const reachable = attached.filter((i) => i.publicIp);
        const where = reachable.length
          ? `, reachable on ${reachable.length} public address${reachable.length === 1 ? "" : "es"}: ${reachable
              .slice(0, 3)
              .map((i) => ownerText(region, i))
              .join(", ")}${reachable.length > 3 ? " and more" : ""}`
          : attached.length
            ? `, attached to ${attached.length} network interface${attached.length === 1 ? "" : "s"}, none with a public address`
            : ", not attached to anything";
        // The check's own severity when something public uses the group, one step down when only private things do, low when nothing does.
        const severity = (own: Severity): Severity | undefined => (reachable.length ? undefined : attached.length ? ONE_LOWER[own] : "low");
        const base = { zone: region.name, resource: `${g.name} (${g.id})`, link: d.securityGroup(region.name, g.id) };
        const chain = (rules: Rule[]) =>
          reachable.length
            ? {
                chain: [
                  ...rules.map((r) => ({ label: "Inbound rule", value: ruleText(r) })),
                  ...reachable.slice(0, 5).map((i) => ({ label: "Reachable from the internet", value: `${ownerText(region, i)} at ${i.publicIp}` })),
                ],
              }
            : null;

        const all = g.open.filter(isAll);
        report("ANW-003", {
          ...base,
          pass: !all.length,
          severity: all.length ? severity("critical") : undefined,
          detail: all.length ? `${all.map(ruleText).join("; ")}${where}` : "",
          evidence: all.length ? chain(all) : null,
        });

        const admin = exposed(g, ADMIN_PORTS);
        report("ANW-001", {
          ...base,
          pass: !admin.length,
          severity: admin.length ? severity("high") : undefined,
          detail: admin.length
            ? `${[...new Set(admin.map((a) => a.name))].join(" and ")}: ${[...new Set(admin.map((a) => ruleText(a.rule)))].join("; ")}${where}`
            : "",
          evidence: admin.length ? chain(admin.map((a) => a.rule)) : null,
        });

        const db = exposed(g, DATABASE_PORTS);
        report("ANW-002", {
          ...base,
          pass: !db.length,
          severity: db.length ? severity("high") : undefined,
          detail: db.length ? `${[...new Set(db.map((a) => a.name))].join(", ")}: ${[...new Set(db.map((a) => ruleText(a.rule)))].join("; ")}${where}` : "",
          evidence: db.length ? chain(db.map((a) => a.rule)) : null,
        });
      }
    }
  },
);
