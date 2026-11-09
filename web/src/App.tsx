// The app shell: session gate, sidebar, top bar with the scope switcher and
// scan progress, and the router. Pages are listed in routes.tsx.

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Breadcrumbs, Button, ButtonGroup, DropdownMenu, Sidebar, Toasty, Tooltip, TooltipProvider, useKumoToastManager } from "@cloudflare/kumo";
import {
  ArrowCircleUpIcon,
  ArrowsClockwiseIcon,
  BuildingsIcon,
  CaretDownIcon,
  CaretUpDownIcon,
  CheckIcon,
  GearIcon,
  GlobeIcon,
  MoonIcon,
  SquaresFourIcon,
  StackIcon,
  SunIcon,
  WarningIcon,
} from "@phosphor-icons/react";
import {
  adoptScope,
  useScrollToHash,
  api,
  ago,
  defaultScope,
  link,
  navigate,
  onApiError,
  plural,
  resolveView,
  scopeKeyFor,
  splitScopeKey,
  PROVIDER_INFO,
  type ProviderId,
  withProvider,
  useLocation,
  useMode,
  useScopeKey,
  withScope,
  type ScanRequest,
  type ScanStatus,
  type Session,
} from "./lib.ts";
import { ShellContext, useShell, type Shell } from "./shell.tsx";
import { NAV_GROUPS, ROUTES, ReportPage, matchRoute } from "./routes.tsx";
import { Loading, NoRows, Page, ProviderIcon } from "./components/ui.tsx";
import { Wordmark } from "./components/brand.tsx";
import { SetupPage } from "./pages/Setup.tsx";
import { LoginPage } from "./pages/Login.tsx";

export function App() {
  return (
    <Toasty>
      <TooltipProvider delay={300}>
        <Root />
      </TooltipProvider>
    </Toasty>
  );
}

function Root() {
  const [session, setSession] = useState<Session | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const refreshSession = useCallback(async () => {
    try {
      setSession(await api<Session>("/api/session"));
      setFailed(null);
    } catch (e) {
      setFailed((e as Error).message);
    }
  }, []);
  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);
  // Sign-in, setup and unknown-scope errors from any request refresh the session.
  useEffect(() => onApiError(() => void refreshSession()), [refreshSession]);
  const { path } = useLocation();

  if (failed) {
    return (
      <div className="mx-auto max-w-md p-10 text-sm">
        <p className="font-medium text-kumo-danger">The Edgewatch server is unreachable.</p>
        <p className="mt-1 text-kumo-subtle">{failed}</p>
        <Button className="mt-4" size="sm" onClick={() => void refreshSession()}>
          Try again
        </Button>
      </div>
    );
  }
  if (!session) return <Loading />;
  if (session.authRequired && !session.authenticated) return <LoginPage onDone={refreshSession} />;
  if (!session.configured) return <SetupPage onDone={refreshSession} />;
  return <AppShell session={session} refreshSession={refreshSession} standalone={path === "/report"} />;
}

/** Status checks that fail in a row before the app says the server is unreachable. */
const POLL_FAILURES_SHOWN = 3;

function AppShell({ session, refreshSession, standalone }: { session: Session; refreshSession: () => Promise<void>; standalone: boolean }) {
  useScrollToHash();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [dataVersion, setDataVersion] = useState(0);
  const toasts = useKumoToastManager();
  const wasRunning = useRef(false);
  const failedPolls = useRef(0);
  const [key, setScope] = useScopeKey();
  // A removed account or entity falls back to the default view.
  const view = useMemo(() => (key && resolveView(session, key)) || resolveView(session, defaultScope(session))!, [session, key]);
  const scope = view.key;
  const scoped = useCallback((path: string) => withScope(path, scope), [scope]);
  // The URL always says which scope it shows, so it can be shared.
  useEffect(() => adoptScope(scope), [scope]);

  const poll = useCallback(async () => {
    try {
      const s = await api<ScanStatus>(withScope("/api/scan/status", scope));
      setStatus(s);
      if (wasRunning.current && !s.running) {
        setDataVersion((v) => v + 1);
        if (s.lastFailed && Date.parse(s.lastFailed.finishedAt) > Date.now() - 10 * 60_000) {
          toasts.add({ title: `Scan of ${s.lastFailed.account} failed`, description: s.lastFailed.error, variant: "error" });
        } else toasts.add({ title: "Scan complete", description: "Findings and scores are up to date.", variant: "success" });
        void refreshSession();
      }
      wasRunning.current = s.running;
      if (failedPolls.current >= POLL_FAILURES_SHOWN) toasts.add({ title: "Connected to Edgewatch again", variant: "success" });
      failedPolls.current = 0;
    } catch (e) {
      // A server that stopped mid-scan would otherwise leave "Scanning…" on screen forever.
      if (++failedPolls.current === POLL_FAILURES_SHOWN) {
        setStatus((s) => s && { ...s, running: false });
        toasts.add({ title: "Can't reach Edgewatch", description: `${(e as Error).message}. Checking again in a moment.`, variant: "error" });
      }
    }
  }, [toasts, scope, refreshSession]);

  useEffect(() => {
    void poll();
    const t = setInterval(poll, status?.running ? 2000 : 30_000);
    return () => clearInterval(t);
  }, [poll, status?.running]);

  const startScan = useCallback(
    async (scopeKey?: string, opts?: { every?: boolean }) => {
      try {
        const body: ScanRequest = { scope: scopeKey ?? scope, ...(opts?.every && { every: true }) };
        await api("/api/scan", { method: "POST", body });
        wasRunning.current = true;
        await poll();
      } catch (e) {
        toasts.add({ title: "Couldn't start a scan", description: (e as Error).message, variant: "error" });
      }
    },
    [poll, toasts, scope],
  );

  const shell: Shell = { session, refreshSession, status, dataVersion, startScan, view, setScope, scoped, multi: view.accounts.length > 1 };
  if (standalone)
    return (
      <ShellContext.Provider value={shell}>
        <Suspense fallback={<Loading />}>
          <ReportPage params={{}} />
        </Suspense>
      </ShellContext.Provider>
    );

  return (
    <ShellContext.Provider value={shell}>
      <Sidebar.Provider defaultOpen collapsible="icon" className="h-svh overflow-hidden">
        <Nav />
        <div id="scroll-root" className="flex h-svh min-w-0 flex-1 flex-col overflow-y-auto">
          <TopBar />
          <main className="flex-1 bg-kumo-canvas">
            <Suspense fallback={<Loading />}>
              <Router />
            </Suspense>
          </main>
        </div>
      </Sidebar.Provider>
    </ShellContext.Provider>
  );
}

function Router() {
  const { path } = useLocation();
  const m = matchRoute(path);
  // Name the tab and history entry after the page.
  const label = m?.route.label;
  useEffect(() => {
    document.title = label ? `${label} · Edgewatch` : "Edgewatch";
  }, [label]);
  if (!m)
    return (
      <Page title="Page not found">
        <NoRows>There's nothing at this address.</NoRows>
      </Page>
    );
  const P = m.route.page;
  return <P params={m.params} />;
}

const isActive = (path: string, to: string) => (to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`));

function Nav() {
  const { path } = useLocation();
  const { session, view } = useShell();
  const current = matchRoute(path)?.route;
  // Pages for one provider only show when the view has an account on it (all accounts before any are connected).
  const inView = new Set(view.accounts.map((a) => a.provider));
  const shown = (r: (typeof ROUTES)[number]) => !r.hidden && (!r.providers || !inView.size || r.providers.some((p) => inView.has(p)));
  return (
    <Sidebar>
      <Sidebar.Header className="flex h-14 items-center border-b border-kumo-hairline">
        <a {...link("/")} className="flex items-center gap-2 px-2">
          <Wordmark />
        </a>
      </Sidebar.Header>
      <Sidebar.Content>
        {NAV_GROUPS.filter((g) => ROUTES.some((r) => r.group === g && shown(r))).map((g) => (
          <Sidebar.Group key={g}>
            <Sidebar.GroupLabel>{g}</Sidebar.GroupLabel>
            <Sidebar.Menu>
              {ROUTES.filter((r) => r.group === g && shown(r)).map((r) => (
                <Sidebar.MenuButton
                  key={r.path}
                  icon={r.icon}
                  {...link(r.path)}
                  active={isActive(path, current?.parent || r.path) && (current?.parent ? r.path === current.parent : true)}
                  tooltip={r.label}
                >
                  {r.label}
                </Sidebar.MenuButton>
              ))}
            </Sidebar.Menu>
          </Sidebar.Group>
        ))}
      </Sidebar.Content>
      <Sidebar.Footer>
        <div className="px-2 pb-2 text-xs leading-relaxed whitespace-normal text-kumo-subtle group-data-[state=collapsed]/sidebar:hidden">
          <span className="flex flex-wrap items-center gap-x-1.5">
            Edgewatch {session.version}
            {session.update?.latest && (
              <a
                {...link("/settings#updates")}
                title={`Edgewatch ${session.update.latest.version} is available${session.update.breaking ? ", with breaking changes" : ""}`}
                className={`inline-flex items-center gap-1 font-medium whitespace-nowrap ${session.update.breaking ? "text-kumo-warning" : "text-kumo-link"}`}
              >
                {session.update.breaking ? <WarningIcon weight="fill" aria-hidden /> : <ArrowCircleUpIcon weight="fill" aria-hidden />}
                {session.update.latest.version} available
              </a>
            )}
          </span>
          Not affiliated with any provider.
        </div>
      </Sidebar.Footer>
    </Sidebar>
  );
}

function TopBar() {
  const { session, status } = useShell();
  const { path } = useLocation();
  const [mode, setMode] = useMode();
  const route = matchRoute(path)?.route;
  const parent = route?.parent ? ROUTES.find((r) => r.path === route.parent) : null;
  const running = !!status?.running;
  const name = (id: string | null) => session.accounts?.find((a) => a.id === id)?.display || "account";
  const progress = running
    ? `${(session.accounts?.length || 0) > 1 ? `${name(status!.accountId)}: ` : ""}${status?.phase || "Scanning"}${status?.total ? ` (${status.done}/${status.total})` : ""}${status?.queued.length ? `, ${status.queued.length} more queued` : ""}…`
    : status?.lastScanAt
      ? `Last scan ${ago(status.lastScanAt)}`
      : "Not scanned yet";
  return (
    <div className="no-print sticky top-0 z-10 shrink-0 border-b border-kumo-hairline bg-kumo-base">
      <div className="flex h-14 items-center gap-3 px-4">
        <Sidebar.Trigger />
        <Breadcrumbs size="sm" className="min-w-0">
          {route?.global ? (
            <span className="shrink-0 text-kumo-subtle">Applies to every account</span>
          ) : (
            <>
              <ScopeSwitcher />
              <ProviderSwitch />
            </>
          )}
          {/* On phones the sidebar names the page; the scope gets the room. */}
          {route && (
            <span className="hidden sm:contents">
              <Breadcrumbs.Separator />
              {parent && (
                <>
                  <a {...link(parent.path)} className="hidden shrink-0 text-kumo-subtle hover:text-kumo-default sm:inline">
                    {parent.label}
                  </a>
                  <span className="hidden sm:contents">
                    <Breadcrumbs.Separator />
                  </span>
                </>
              )}
              <Breadcrumbs.Current>{route.label}</Breadcrumbs.Current>
            </span>
          )}
        </Breadcrumbs>
        <div className="ml-auto flex shrink-0 items-center gap-2">
          <span className="mr-1 hidden truncate text-sm text-kumo-subtle lg:inline" aria-live="polite">
            {progress}
          </span>
          <Tooltip
            content={mode === "dark" ? "Light mode" : "Dark mode"}
            render={
              <Button
                variant="ghost"
                size="sm"
                shape="square"
                aria-label="Toggle color mode"
                icon={mode === "dark" ? <SunIcon /> : <MoonIcon />}
                onClick={() => setMode(mode === "dark" ? "light" : "dark")}
              />
            }
          />
          <ScanButton />
        </div>
      </div>
      {/* Below lg the progress line has no room in the bar; a thin strip shows it while scanning. */}
      {running && (
        <div className="truncate border-t border-kumo-hairline px-4 py-1 text-xs text-kumo-subtle lg:hidden" aria-hidden>
          {progress}
        </div>
      )}
    </div>
  );
}

/**
 * "Run scan" scans what's in view: the selected account, or the entity or "All accounts"
 * when one of those is selected. The menu beside it scans more: the whole entity, or every
 * account in every entity (including entities kept out of "All accounts").
 */
function ScanButton() {
  const { session, status, startScan, view } = useShell();
  const accounts = session.accounts || [];
  const busy = !!status?.running && !!status?.inScope;
  const entityAccounts = view.entity ? accounts.filter((a) => a.entityId === view.entity!.id) : [];
  const entityCount = new Set(accounts.map((a) => a.entityId)).size;
  const what = view.kind === "account" ? view.label : `the ${plural(view.accounts.length, "account")} in ${view.kind === "all" ? "All accounts" : view.label}`;
  const primary = (
    <Button variant="primary" size="sm" icon={<ArrowsClockwiseIcon />} loading={busy} disabled={busy} onClick={() => startScan()}>
      {busy ? "Scanning" : "Run scan"}
    </Button>
  );
  if (accounts.length < 2) return primary;
  return (
    <ButtonGroup aria-label="Run scan">
      <Tooltip content={`Scans ${what}`} render={primary} />
      <DropdownMenu>
        <DropdownMenu.Trigger render={<Button variant="primary" size="sm" shape="square" aria-label="More ways to scan" icon={<CaretDownIcon />} />} />
        <DropdownMenu.Content align="end" className="min-w-72">
          {view.kind === "account" && (
            <DropdownMenu.Item icon={<GlobeIcon />} onClick={() => startScan()}>
              <span className="flex-1 truncate">Scan {view.label}</span>
              <span className="text-kumo-subtle">This account</span>
            </DropdownMenu.Item>
          )}
          {view.entity && entityAccounts.length > 1 && (
            <DropdownMenu.Item icon={<BuildingsIcon />} onClick={() => startScan(scopeKeyFor.entity(view.entity!.id))}>
              <span className="flex-1 truncate">Scan all of {view.entity.name}</span>
              <span className="text-kumo-subtle">{plural(entityAccounts.length, "account")}</span>
            </DropdownMenu.Item>
          )}
          {view.kind === "all" && (
            <DropdownMenu.Item icon={<SquaresFourIcon />} onClick={() => startScan()}>
              <span className="flex-1">Scan All accounts</span>
              <span className="text-kumo-subtle">{plural(view.accounts.length, "account")}</span>
            </DropdownMenu.Item>
          )}
          <DropdownMenu.Item icon={<SquaresFourIcon />} onClick={() => startScan(undefined, { every: true })}>
            <span className="flex-1">Scan every account</span>
            <span className="text-kumo-subtle">
              {plural(accounts.length, "account")} in {plural(entityCount, "entity", "entities")}
            </span>
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu>
    </ButtonGroup>
  );
}

/**
 * Chooses what the dashboard shows: every account included in "All accounts",
 * one entity, or one account. With a single account it's just a label.
 */
function ScopeSwitcher() {
  const { session, view, setScope } = useShell();
  const accounts = session.accounts || [],
    entities = session.entities || [];
  // One icon per level, matching the menu: all accounts, an entity, a single account.
  const icon =
    view.kind === "account" || accounts.length < 2 ? (
      <ProviderIcon provider={view.accounts[0]?.provider ?? "cloudflare"} className="h-4 w-4 text-kumo-default" />
    ) : view.kind === "entity" ? (
      <BuildingsIcon className="shrink-0" />
    ) : (
      <SquaresFourIcon className="shrink-0" />
    );
  if (accounts.length < 2) {
    return (
      <span className="inline-flex min-w-0 items-center gap-1.5 text-kumo-subtle">
        {icon}
        <span className="truncate">{view.label}</span>
      </span>
    );
  }
  const all = resolveView(session, "all")!;
  const excluded = entities.filter((e) => !e.includeInAll && accounts.some((a) => a.entityId === e.id));
  const providerCount = new Set(accounts.map((a) => a.provider)).size;
  // Picking another view keeps the provider filter; the new view drops it if it has no account on that provider.
  const pick = (k: string) => () => setScope(withProvider(k, view.provider));
  const base = splitScopeKey(view.key).base;
  const mark = (k: string) => (base === k ? <CheckIcon className="text-kumo-brand" /> : <span className="inline-block w-4" />);
  return (
    <DropdownMenu>
      <DropdownMenu.Trigger
        render={
          <button
            type="button"
            aria-label="Choose accounts to show"
            className="-mx-1.5 inline-flex min-w-0 cursor-pointer items-center gap-1.5 rounded-md px-1.5 py-1 text-kumo-default hover:bg-kumo-tint"
          >
            {icon}
            {view.kind === "account" && view.entity && (
              <span className="hidden min-w-0 max-w-40 shrink-[4] truncate text-kumo-subtle lg:inline">{view.entity.name} /</span>
            )}
            <span className="min-w-0 max-w-56 truncate font-medium">{view.label}</span>
            {view.kind !== "account" && <span className="hidden shrink-0 text-kumo-subtle sm:inline">{view.accounts.length}</span>}
            <CaretUpDownIcon className="shrink-0 text-kumo-subtle" />
          </button>
        }
      />
      <DropdownMenu.Content align="start" className="max-h-[70vh] min-w-72 overflow-y-auto">
        {all.accounts.length > 0 && (
          <>
            <DropdownMenu.Item icon={mark("all")} onClick={pick("all")}>
              <span className="flex-1">All accounts</span>
              <span className="text-kumo-subtle">{all.accounts.length}</span>
            </DropdownMenu.Item>
            {excluded.length > 0 && <div className="px-2 pb-1.5 pl-9 text-xs text-kumo-subtle">Leaves out {excluded.map((e) => e.name).join(", ")}</div>}
            <DropdownMenu.Separator />
          </>
        )}
        {entities
          .filter((e) => accounts.some((a) => a.entityId === e.id))
          .map((e, i) => {
            const mine = accounts.filter((a) => a.entityId === e.id);
            return (
              <DropdownMenu.Group key={e.id}>
                {i > 0 && <DropdownMenu.Separator />}
                {/* The entity is a heading at the menu's edge; its accounts sit indented beneath it. */}
                <DropdownMenu.Label className="flex items-center gap-2 pt-2 pb-1 text-xs font-semibold tracking-wide text-kumo-subtle uppercase">
                  <span data-kumo-part="icon" className="inline-flex shrink-0">
                    <BuildingsIcon className="h-4 w-4" />
                  </span>
                  <span className="flex-1 truncate">{e.name}</span>
                  <span className="shrink-0 font-normal tracking-normal normal-case">{e.includeInAll ? plural(mine.length, "account") : "Kept separate"}</span>
                </DropdownMenu.Label>
                {mine.length > 1 && (
                  <DropdownMenu.Item className="pl-6" icon={mark(`e:${e.id}`)} onClick={pick(`e:${e.id}`)}>
                    <SquaresFourIcon className="h-4 w-4 shrink-0 text-kumo-subtle" />
                    <span className="flex-1">All of {e.name}</span>
                  </DropdownMenu.Item>
                )}
                {mine.map((a) => (
                  <DropdownMenu.Item key={a.id} className="pl-6" icon={mark(`a:${a.id}`)} onClick={pick(`a:${a.id}`)}>
                    <ProviderIcon provider={a.provider} />
                    <span className="flex-1 truncate">{a.display}</span>
                    {providerCount > 1 && <span className="text-kumo-subtle">{PROVIDER_INFO[a.provider].label}</span>}
                  </DropdownMenu.Item>
                ))}
              </DropdownMenu.Group>
            );
          })}
        <DropdownMenu.Separator />
        <DropdownMenu.Item icon={<GearIcon />} onClick={() => navigate("/accounts")}>
          Manage accounts and entities
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu>
  );
}

/**
 * Narrows the view to one provider, or shows every provider. Only shown when the view
 * has accounts on more than one; it scales to any number of providers.
 */
function ProviderSwitch() {
  const { view, setScope } = useShell();
  if (view.providers.length < 2) return null;
  const pick = (p: ProviderId | null) => () => setScope(withProvider(view.key, p));
  const mark = (p: ProviderId | null) => (view.provider === p ? <CheckIcon className="text-kumo-brand" /> : <span className="inline-block w-4" />);
  return (
    <>
      <Breadcrumbs.Separator />
      <DropdownMenu>
        <DropdownMenu.Trigger
          render={
            <button
              type="button"
              aria-label="Choose a provider"
              className="-mx-1.5 inline-flex min-w-0 shrink-0 cursor-pointer items-center gap-1.5 rounded-md px-1.5 py-1 text-kumo-default hover:bg-kumo-tint"
            >
              {view.provider ? <ProviderIcon provider={view.provider} className="h-4 w-4 text-kumo-default" /> : <StackIcon className="shrink-0" />}
              <span className="font-medium">{view.provider ? PROVIDER_INFO[view.provider].label : "All providers"}</span>
              <CaretUpDownIcon className="shrink-0 text-kumo-subtle" />
            </button>
          }
        />
        <DropdownMenu.Content align="start" className="min-w-56">
          <DropdownMenu.Item icon={mark(null)} onClick={pick(null)}>
            <StackIcon className="h-4 w-4 shrink-0 text-kumo-subtle" />
            <span className="flex-1">All providers</span>
          </DropdownMenu.Item>
          <DropdownMenu.Separator />
          {view.providers.map((p) => (
            <DropdownMenu.Item key={p} icon={mark(p)} onClick={pick(p)}>
              <ProviderIcon provider={p} />
              <span className="flex-1">{PROVIDER_INFO[p].label}</span>
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu>
    </>
  );
}
