// RDS databases: reachable from the internet, stored unencrypted, or without
// automated backups. A public database whose security group also lets the
// internet reach its port is the worst case, and is reported as such.

import { defineChecks, opens } from "./define.ts";

export default defineChecks(
  {
    "ADB-001": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding",
      requires: ["databases", "securityGroups"],
      attackPath: true,
      title: "Database is publicly accessible",
      why: "The database has a public address. Only its security group and its password keep the internet out, and one loosened rule exposes it.",
      fix: "1. In RDS → the database → Modify → Connectivity → Additional configuration, choose Not publicly accessible. 2. Reach it from inside the VPC, through a VPN, or with Session Manager port forwarding.",
    },
    "ADB-002": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
      requires: ["databases"],
      title: "Database storage isn't encrypted",
      why: "Its disks, automated backups and snapshots are stored in the clear, and an unencrypted snapshot can be shared or copied to another account as it is.",
      fix: "Encryption can't be turned on in place. 1. Take a snapshot. 2. Copy the snapshot with encryption enabled. 3. Restore a new database from the encrypted copy and switch the application to it.",
    },
    "ADB-003": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
      requires: ["databases"],
      title: "Database has no automated backups",
      why: "With retention set to zero there are no daily backups and no point-in-time recovery. A bad migration, a deleted table or ransomware can't be undone.",
      fix: "In RDS → the database → Modify → Backup, set the backup retention period to at least 7 days.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      for (const db of r.databases ?? []) {
        const base = { zone: r.name, resource: db.id, link: d.database(r.name, db.id) };
        const groups = (r.securityGroups ?? []).filter((g) => db.securityGroups.includes(g.id));
        const open = db.port != null ? groups.filter((g) => opens(g, db.port!)) : [];
        report("ADB-001", {
          ...base,
          pass: !db.public,
          // Reachable now is critical; a public address behind closed groups needs one more mistake.
          severity: db.public ? (open.length ? "critical" : "medium") : undefined,
          detail: db.public
            ? open.length
              ? `Public address, and ${open.map((g) => g.name).join(", ")} allows port ${db.port} from the internet`
              : "Has a public address. Its security groups keep the internet out today, so one loosened rule exposes it"
            : "",
          evidence:
            db.public && open.length
              ? {
                  chain: [
                    { label: "Database", value: `${db.id} (${db.engine}) is publicly accessible on port ${db.port}` },
                    ...open.map((g) => ({ label: "Security group", value: `${g.name} (${g.id}) allows port ${db.port} from the internet` })),
                  ],
                }
              : null,
        });
        report("ADB-002", { ...base, pass: db.encrypted, detail: db.encrypted ? "" : `${db.engine} storage is unencrypted` });
        if (!db.replica) report("ADB-003", { ...base, pass: db.backupDays > 0, detail: db.backupDays > 0 ? "" : "Backup retention is 0 days" });
      }
    }
  },
);
