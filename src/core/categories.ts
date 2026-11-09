// Finding categories, in the order the dashboard lists them, shared by every
// provider. Each category is scored separately and the overall score is their
// average; a category none of an account's checks use doesn't count.

export const CATEGORIES = [
  "Attack surface",
  "Traffic",
  "Identity & access",
  "Zero Trust",
  "Deployments",
  "Secrets",
  "TLS & HTTPS",
  "WAF & bots",
  "DNS",
  "Email",
  "Platform",
  "Monitoring",
  "Change risk",
  "Cost & usage",
] as const;

export type Category = (typeof CATEGORIES)[number];
