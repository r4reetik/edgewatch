// Kumo TimeseriesChart wired to a tree-shaken ECharts build.

import * as echarts from "echarts/core";
import { LineChart, BarChart } from "echarts/charts";
import { GridComponent, TooltipComponent, LegendComponent, MarkLineComponent, AriaComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { ChartPalette, TimeseriesChart } from "@cloudflare/kumo";
import { useMode, SCORED_SEVERITIES, SEVERITY_LABEL } from "../lib.ts";
import type { TrendPoint } from "../lib.ts";
type Point = TrendPoint;

echarts.use([LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent, MarkLineComponent, AriaComponent, CanvasRenderer]);

const dayFmt = (ms: number) => new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric" });
const timeFmt = (ms: number) => new Date(ms).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
/** Days for a multi-day trend; times when every scan so far happened within a day or two. */
const tickFmt = (points: Point[]) => (points.length && Date.parse(points[points.length - 1].at) - Date.parse(points[0].at) < 2 * 86_400_000 ? timeFmt : dayFmt);

/**
 * Severity series colors, checked with the dataviz palette validator for each
 * mode (lightness band, chroma, color-blind and normal-vision separation).
 * Red and orange for the two urgent levels, then distinct hues, so no two lines
 * collapse for deuteranopes. The legend names every series and shows its
 * current count, so color is never the only signal.
 */
const SEVERITY_SERIES = {
  light: { critical: "#c62828", high: "#e8740c", medium: "#7b61ff", low: "#2a9d8f" },
  dark: { critical: "#e5484d", high: "#c08a00", medium: "#8e7ff0", low: "#16a08f" },
} as const;

export const severityColors = (dark: boolean): Record<string, string> => SEVERITY_SERIES[dark ? "dark" : "light"];
const stampFmt = (ms: number) => new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/** A trend needs two points; until then say so instead of drawing an empty axis. */
function NotEnough({ points }: { points: Point[] }) {
  return (
    <div className="flex h-[220px] flex-col items-center justify-center gap-1 text-center">
      <div className="text-sm text-kumo-default">The trend appears after the second scan</div>
      <div className="text-xs text-kumo-subtle">{points.length ? "Scans run daily, or click Run scan." : "No scans yet."}</div>
    </div>
  );
}

export function ScoreChart({ points }: { points: Point[] }) {
  const [mode] = useMode();
  if (points.length < 2) return <NotEnough points={points} />;
  const dark = mode === "dark";
  const data = points.filter((p) => p.score != null).map((p) => [Date.parse(p.at), p.score as number] as [number, number]);
  return (
    <TimeseriesChart
      echarts={echarts}
      isDarkMode={dark}
      height={220}
      gradient
      data={[{ name: "Posture score", data, color: ChartPalette.categorical(0, dark) }]}
      yAxisTickCount={5}
      xAxisTickFormat={tickFmt(points)}
      tooltipTimestampFormat={stampFmt}
      tooltipValueFormat={(v) => `${Math.round(v)} / 100`}
      // Lines at 0 and 100 pin the axis to the full range, so a flat score of 50 sits mid-chart.
      thresholds={[
        { value: 100, color: dark ? "#383835" : "#c3c2b7" },
        { value: 0, color: dark ? "#383835" : "#c3c2b7" },
      ]}
      ariaDescription="Posture score at each scan, out of 100."
    />
  );
}

/** Open findings per severity at each scan. Severity uses the chart palette's semantic colors plus labels in the legend and tooltip. */
export function SeverityChart({ points }: { points: Point[] }) {
  const [mode] = useMode();
  if (points.length < 2) return <NotEnough points={points} />;
  const dark = mode === "dark";
  const colors = severityColors(dark);
  const data = SCORED_SEVERITIES.map((s) => ({
    name: SEVERITY_LABEL[s],
    color: colors[s],
    data: points.map((p) => [Date.parse(p.at), p.counts[s] ?? 0] as [number, number]),
  }));
  return (
    <TimeseriesChart
      echarts={echarts}
      isDarkMode={dark}
      height={220}
      data={data}
      yAxisMinInterval={1}
      xAxisTickFormat={tickFmt(points)}
      tooltipTimestampFormat={stampFmt}
      ariaDescription="Open findings by severity at each scan."
    />
  );
}

/** Legend with each severity's latest count, so lines are identified by label as well as color. */
export function SeverityLegend({ latest }: { latest?: Partial<Record<string, number>> }) {
  const [mode] = useMode();
  const colors = severityColors(mode === "dark");
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-kumo-subtle">
      {SCORED_SEVERITIES.map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5">
          <span className="h-[3px] w-3.5 rounded-full" style={{ background: colors[s] }} />
          {SEVERITY_LABEL[s]}
          {latest && <span className="text-kumo-default tabular-nums">{latest[s] ?? 0}</span>}
        </span>
      ))}
    </div>
  );
}

/** Both trend charts, or one line saying when they'll appear. */
export function TrendCharts({
  points,
  latest,
  Card,
}: {
  points: Point[];
  latest: Partial<Record<string, number>>;
  Card: (p: { title: string; actions?: React.ReactNode; children: React.ReactNode }) => React.ReactNode;
}) {
  if (points.length < 2) {
    return <p className="text-sm text-kumo-subtle">Score and severity trends appear after the second scan. Scans run daily, or use Run scan.</p>;
  }
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title="Posture score">
        <ScoreChart points={points} />
      </Card>
      <Card title="Open findings by severity">
        <div className="mb-2">
          <SeverityLegend latest={latest} />
        </div>
        <SeverityChart points={points} />
      </Card>
    </div>
  );
}
