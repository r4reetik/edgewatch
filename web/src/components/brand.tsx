// Edgewatch's own mark: a shield with a check. Deliberately not Cloudflare's logo.

export function Mark({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className="shrink-0">
      <rect width="32" height="32" rx="7" className="fill-kumo-brand" />
      <path d="M16 6.5 8 9.6v6.2c0 5 3.4 9 8 10.2 4.6-1.2 8-5.2 8-10.2V9.6z" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinejoin="round" />
      <path d="m12.4 16 2.6 2.6 4.8-5" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="flex items-center gap-2">
      <Mark />
      <span className="text-base font-semibold tracking-tight text-kumo-default">Edgewatch</span>
    </span>
  );
}
