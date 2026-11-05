// Finding categories, in the order the dashboard lists them. Each category is
// scored separately and the overall score is their average.

export const CATEGORIES = [
  "Attack surface",
  "Traffic",
  "Identity & access",
  "Zero Trust",
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
