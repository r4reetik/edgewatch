// Shapes of the Cloudflare API payloads the checks read. Only the fields we use
// are listed, and anything the API may omit is optional. Rarely read payloads
// stay loosely typed as `Api` (see types.ts).

export interface DnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  proxied?: boolean;
  ttl?: number;
  comment?: string | null;
  created_on: string;
  modified_on: string;
}

export interface Rule {
  id?: string;
  description?: string;
  expression?: string;
  action?: string;
  enabled?: boolean;
  /** Rule-specific parameters: execute targets, skip phases, overrides, headers, settings. */
  action_parameters?: Record<string, any>;
  ratelimit?: { requests_per_period?: number; period?: number; characteristics?: string[]; counting_expression?: string };
  logging?: { enabled?: boolean };
}

export interface Ruleset {
  id?: string;
  name?: string;
  phase?: string;
  rules?: Rule[];
}

export interface ZoneSettings {
  ssl?: string;
  min_tls_version?: string;
  always_use_https?: string;
  tls_1_3?: string;
  automatic_https_rewrites?: string;
  security_level?: string;
  browser_check?: string;
  development_mode?: string;
  "0rtt"?: string;
  ciphers?: string[];
  cname_flattening?: string;
  security_header?: { strict_transport_security?: { enabled?: boolean; max_age?: number; include_subdomains?: boolean; preload?: boolean } };
  [key: string]: any;
}

export interface Member {
  id?: string;
  status?: string;
  email?: string;
  user?: { email?: string; two_factor_authentication_enabled?: boolean };
  roles?: { name: string }[];
  policies?: { access?: string; permission_groups?: { name: string }[]; resource_groups?: { name?: string; scope?: any }[] }[];
}

/** One Access rule: exactly one key is set (email, email_domain, everyone, group, ip, ...). */
export interface AccessRule {
  email?: { email: string };
  email_domain?: { domain: string };
  everyone?: Record<string, never>;
  group?: { id: string };
  ip?: { ip: string };
  [key: string]: any;
}

export interface AccessPolicy {
  id?: string;
  name?: string;
  decision?: string;
  include?: AccessRule[];
  exclude?: AccessRule[];
  require?: AccessRule[];
  app_count?: number;
  session_duration?: string;
}

export interface AccessApp {
  id?: string;
  name?: string;
  domain?: string;
  type: string;
  session_duration?: string;
  policies?: AccessPolicy[];
  self_hosted_domains?: string[];
  destinations?: { uri?: string; type?: string }[];
  allowed_idps?: string[];
  http_only_cookie_attribute?: boolean;
  same_site_cookie_attribute?: string;
  enable_binding_cookie?: boolean;
  cors_headers?: { allow_all_origins?: boolean; allow_credentials?: boolean; allowed_origins?: string[] };
}

export interface AccessGroup {
  id: string;
  name: string;
  include?: AccessRule[];
  exclude?: AccessRule[];
  require?: AccessRule[];
}

export interface AccessOrg {
  auth_domain?: string;
  deny_unmatched_requests?: boolean;
  mfa_required_for_all_apps?: boolean;
  session_duration?: string;
  service_token_inactivity?: { enabled?: boolean; inactivity_threshold_days?: number };
}

export interface AccessUser {
  id: string;
  email?: string;
  name?: string;
  access_seat?: boolean;
  gateway_seat?: boolean;
  last_successful_login?: string | null;
}

export interface ServiceToken {
  id?: string;
  name: string;
  duration?: string;
  created_at?: string;
  expires_at?: string;
  last_seen_at?: string | null;
  enabled?: boolean;
  leak_reported_at?: string | null;
}

export interface Tunnel {
  id: string;
  name: string;
  status?: string;
  conns_active_at?: string | null;
  deleted_at?: string | null;
  config_src?: string;
  connections?: { client_version?: string; opened_at?: string; origin_ip?: string }[];
}

export interface IngressRule {
  hostname?: string;
  service?: string;
  path?: string;
  originRequest?: { noTLSVerify?: boolean; access?: { required?: boolean } };
}

export interface AuditEntry {
  when: string;
  action?: { type?: string; result?: boolean; info?: string };
  actor?: { email?: string; type?: string; ip?: string };
  resource?: { type?: string; id?: string };
  metadata?: Record<string, any>;
  oldValue?: string;
  newValue?: string;
  oldValueJson?: any;
  newValueJson?: any;
}

export interface CertificatePack {
  id?: string;
  type: string;
  status: string;
  hosts?: string[];
  certificates?: { expires_on: string; status?: string }[];
}
export interface OriginCertificate {
  id?: string;
  hostnames?: string[];
  expires_on?: string;
}
export interface ExpiringCertificate {
  id?: string;
  hosts?: string[];
  hostnames?: string[];
  common_name?: string;
  name?: string;
  expires_on?: string;
  status?: string;
  issuer?: string;
}

export interface AccountToken {
  id: string;
  name: string;
  status: string;
  expires_on?: string | null;
  last_used_on?: string | null;
  issued_on?: string;
  condition?: { request_ip?: { in?: string[]; not_in?: string[] } };
  policies?: { effect?: string; permission_groups?: { id?: string; name?: string }[]; resources?: Record<string, string | Record<string, string>> }[];
}

export interface DeviceProfile {
  policy_id?: string;
  name?: string;
  default?: boolean;
  enabled?: boolean;
  match?: string;
  switch_locked?: boolean;
  allowed_to_leave?: boolean;
  allow_mode_switch?: boolean;
  auto_connect?: number;
}

export interface GatewayConfig {
  settings?: {
    tls_decrypt?: { enabled?: boolean };
    activity_log?: { enabled?: boolean };
    antivirus?: { enabled_download_phase?: boolean; enabled_upload_phase?: boolean; fail_closed?: boolean };
    [key: string]: any;
  };
}

export interface GatewayRule {
  id?: string;
  name?: string;
  action?: string;
  enabled?: boolean;
  filters?: string[];
  traffic?: string;
  rule_settings?: { check_session?: { enforce?: boolean; duration?: string } };
}
export interface PrivateRoute {
  network: string;
  tunnel_id?: string;
  tunnel_name?: string;
  comment?: string;
  deleted_at?: string | null;
}
export interface IpAccessRule {
  id: string;
  mode: string;
  notes?: string;
  configuration?: { target?: string; value?: string };
  scope?: { type?: string };
}
export interface SpectrumApp {
  id: string;
  protocol: string;
  dns?: { name?: string };
  tls?: string;
  ip_firewall?: boolean;
  origin_direct?: string[];
}
export interface LoadBalancer {
  id: string;
  name: string;
  proxied?: boolean;
  enabled?: boolean;
  default_pools?: string[];
  fallback_pool?: string;
}
export interface LbPool {
  id: string;
  name: string;
  enabled?: boolean;
  origins?: { name?: string; address?: string; enabled?: boolean }[];
}
export interface HealthCheck {
  id: string;
  name: string;
  address?: string;
  type?: string;
  status?: string;
  suspended?: boolean;
  http_config?: { allow_insecure?: boolean };
}
export interface WorkerBinding {
  type: string;
  name: string;
  text?: string;
}
export interface WorkerDomain {
  hostname: string;
  service?: string;
  zone_name?: string;
}
export interface PagesProject {
  name: string;
  subdomain?: string;
  domains?: string[];
  source?: { config?: { preview_deployment_setting?: string } };
  deployment_configs?: Record<"preview" | "production", { env_vars?: Record<string, { type?: string; value?: string } | null> }>;
}
export interface R2CorsRule {
  allowed?: { origins?: string[]; methods?: string[]; headers?: string[] };
}
export interface EmailCatchAll {
  enabled?: boolean;
  actions?: { type?: string; value?: string[] }[];
}
export interface WebhookDestination {
  id: string;
  name?: string;
  url?: string;
  type?: string;
  last_success?: string | null;
  last_failure?: string | null;
}
export interface PageShieldScript {
  id: string;
  url: string;
  host?: string;
  malicious_domain_categories?: string[];
  malicious_url_categories?: string[];
  url_reported_malicious?: boolean;
  domain_reported_malicious?: boolean;
  js_integrity_score?: number;
}
export interface HostnameTlsSetting {
  hostname: string;
  value: string;
}
export interface MtlsAssociation {
  hostnames?: string[];
}
