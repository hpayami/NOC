'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  AssetRiskProfile,
  type AssetGraph,
  type AssetGraphNode,
  type RiskLevel,
} from '@noc/shared';

export interface GraphLabels {
  search: string;
  filterRisk: string;
  filterSite: string;
  all: string;
  legendTopology: string;
  legendTraffic: string;
  selectHint: string;
  loading: string;
  risk: string;
  score: string;
  confidence: string;
  basis: string;
  ports: string;
  noPorts: string;
  techniques: string;
  techAlert: string;
  techExposure: string;
  noTechniques: string;
  findings: string;
  findingsWithheld: string;
  noFindings: string;
  alerts: string;
  alertsWithheld: string;
  noAlerts: string;
  neighbors: string;
  noNeighbors: string;
  source: string;
  noEdges: string;
  riskLevels: Record<RiskLevel, string>;
}

const RISK_COLOR: Record<RiskLevel, string> = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
  none: 'var(--color-ok)',
  unknown: 'var(--color-muted)',
};
const SEV_CLASS: Record<string, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
};

interface Pos {
  x: number;
  y: number;
}

/** Deterministic pseudo-random so the layout is stable across renders of the same graph. */
function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Small force-directed layout (repulsion + spring edges + centre gravity), run synchronously.
 * Bounded node counts (≤ 500) keep this well under a frame budget; no dependency added.
 */
function layout(nodes: AssetGraphNode[], edges: AssetGraph['edges'], w: number, h: number) {
  const rnd = mulberry32(nodes.length * 7919 + edges.length);
  const pos = new Map<string, Pos>();
  const vel = new Map<string, Pos>();
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  for (const n of nodes) {
    pos.set(n.id, { x: w / 2 + (rnd() - 0.5) * w * 0.8, y: h / 2 + (rnd() - 0.5) * h * 0.8 });
    vel.set(n.id, { x: 0, y: 0 });
  }
  const links = edges
    .filter((e) => idx.has(e.sourceAssetId) && idx.has(e.targetAssetId))
    .map((e) => ({
      a: e.sourceAssetId,
      b: e.targetAssetId,
      k: e.basis === 'topology' ? 0.08 : 0.04,
    }));
  const iterations = nodes.length > 200 ? 120 : 260;
  const area = w * h;
  const kRep = Math.max(1200, area / Math.max(1, nodes.length) / 2);
  const rest = Math.min(160, Math.sqrt(area / Math.max(1, nodes.length)) * 0.9);
  for (let it = 0; it < iterations; it++) {
    const cool = 1 - it / iterations;
    for (const a of nodes) {
      const pa = pos.get(a.id)!;
      let fx = (w / 2 - pa.x) * 0.002;
      let fy = (h / 2 - pa.y) * 0.002;
      for (const b of nodes) {
        if (a === b) continue;
        const pb = pos.get(b.id)!;
        let dx = pa.x - pb.x;
        let dy = pa.y - pb.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) {
          dx = rnd() - 0.5;
          dy = rnd() - 0.5;
          d2 = 1;
        }
        const f = kRep / d2;
        fx += (dx / Math.sqrt(d2)) * f * 0.02;
        fy += (dy / Math.sqrt(d2)) * f * 0.02;
      }
      const v = vel.get(a.id)!;
      v.x = (v.x + fx) * 0.6;
      v.y = (v.y + fy) * 0.6;
    }
    for (const l of links) {
      const pa = pos.get(l.a)!;
      const pb = pos.get(l.b)!;
      const dx = pb.x - pa.x;
      const dy = pb.y - pa.y;
      const d = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const f = (d - rest) * l.k;
      const va = vel.get(l.a)!;
      const vb = vel.get(l.b)!;
      va.x += (dx / d) * f;
      va.y += (dy / d) * f;
      vb.x -= (dx / d) * f;
      vb.y -= (dy / d) * f;
    }
    for (const n of nodes) {
      const p = pos.get(n.id)!;
      const v = vel.get(n.id)!;
      p.x = Math.min(w - 24, Math.max(24, p.x + v.x * cool));
      p.y = Math.min(h - 24, Math.max(24, p.y + v.y * cool));
    }
  }
  return pos;
}

export function AssetGraphView({ graph, labels }: { graph: AssetGraph; labels: GraphLabels }) {
  const [query, setQuery] = useState('');
  const [risk, setRisk] = useState<'all' | RiskLevel>('all');
  const [site, setSite] = useState<string>('all');
  const [selected, setSelected] = useState<string | null>(null);
  const [profile, setProfile] = useState<AssetRiskProfile | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const W = 960;
  const H = 600;
  const positions = useMemo(() => layout(graph.nodes, graph.edges, W, H), [graph]);
  const sites = useMemo(
    () => [...new Set(graph.nodes.map((n) => n.site).filter((s): s is string => !!s))].sort(),
    [graph],
  );
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return new Set(
      graph.nodes
        .filter((n) => risk === 'all' || n.risk.level === risk)
        .filter((n) => site === 'all' || n.site === site)
        .filter(
          (n) =>
            !q ||
            n.label.toLowerCase().includes(q) ||
            (n.hostname ?? '').toLowerCase().includes(q) ||
            n.ipAddresses.some((ip) => ip.includes(q)),
        )
        .map((n) => n.id),
    );
  }, [graph, query, risk, site]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setProfile(null);
    fetch(`/assets/${selected}/risk`, { cache: 'no-store' })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return AssetRiskProfile.parse(await r.json());
      })
      .then((p) => {
        if (!cancelled) setProfile(p);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const input = 'rounded-md border border-border bg-surface-2 px-2 py-1 text-xs';
  const edgeVisible = (e: AssetGraph['edges'][number]) =>
    visible.has(e.sourceAssetId) && visible.has(e.targetAssetId);
  const maxWeight = Math.max(1, ...graph.edges.map((e) => e.weight));

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <input
            aria-label={labels.search}
            placeholder={labels.search}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className={`ltr w-48 ${input}`}
          />
          <label className="flex items-center gap-1 text-muted">
            {labels.filterRisk}
            <select
              value={risk}
              onChange={(e) => setRisk(e.target.value as 'all' | RiskLevel)}
              className={input}
            >
              <option value="all">{labels.all}</option>
              {(Object.keys(labels.riskLevels) as RiskLevel[]).map((k) => (
                <option key={k} value={k}>
                  {labels.riskLevels[k]}
                </option>
              ))}
            </select>
          </label>
          {sites.length ? (
            <label className="flex items-center gap-1 text-muted">
              {labels.filterSite}
              <select
                value={site}
                onChange={(e) => setSite(e.target.value)}
                className={`ltr ${input}`}
              >
                <option value="all">{labels.all}</option>
                {sites.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          <span className="ms-auto flex items-center gap-3 text-muted">
            <span className="flex items-center gap-1">
              <svg width="24" height="6" aria-hidden="true">
                <line x1="0" y1="3" x2="24" y2="3" stroke="var(--color-accent)" strokeWidth="2" />
              </svg>
              {labels.legendTopology}
            </span>
            <span className="flex items-center gap-1">
              <svg width="24" height="6" aria-hidden="true">
                <line
                  x1="0"
                  y1="3"
                  x2="24"
                  y2="3"
                  stroke="var(--color-muted)"
                  strokeWidth="2"
                  strokeDasharray="4 3"
                />
              </svg>
              {labels.legendTraffic}
            </span>
          </span>
        </div>
        {graph.edges.length === 0 ? <p className="text-xs text-muted">{labels.noEdges}</p> : null}
        <div className="overflow-hidden rounded-lg border border-border bg-surface">
          <svg
            viewBox={`0 0 ${W} ${H}`}
            className="h-auto w-full"
            role="img"
            aria-label="asset dependency graph"
            data-testid="asset-graph"
          >
            {graph.edges.filter(edgeVisible).map((e) => {
              const a = positions.get(e.sourceAssetId)!;
              const b = positions.get(e.targetAssetId)!;
              const touched = selected === e.sourceAssetId || selected === e.targetAssetId;
              return (
                <line
                  key={e.id}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={e.basis === 'topology' ? 'var(--color-accent)' : 'var(--color-muted)'}
                  strokeOpacity={selected && !touched ? 0.25 : 0.8}
                  strokeWidth={
                    e.basis === 'topology'
                      ? 2
                      : 1 + (2.5 * Math.log1p(e.weight)) / Math.log1p(maxWeight)
                  }
                  strokeDasharray={e.basis === 'topology' ? undefined : '5 4'}
                >
                  <title>{e.evidence}</title>
                </line>
              );
            })}
            {graph.nodes
              .filter((n) => visible.has(n.id))
              .map((n) => {
                const p = positions.get(n.id)!;
                const isSel = selected === n.id;
                const r = 7 + Math.min(6, n.openFindings + n.openAlerts);
                return (
                  <g
                    key={n.id}
                    transform={`translate(${p.x},${p.y})`}
                    onClick={() => setSelected(n.id)}
                    className="cursor-pointer"
                    data-testid="asset-node"
                    data-risk={n.risk.level}
                  >
                    <circle
                      r={r}
                      fill={RISK_COLOR[n.risk.level]}
                      fillOpacity={0.9}
                      stroke={isSel ? 'var(--color-fg)' : 'var(--color-bg)'}
                      strokeWidth={isSel ? 3 : 1.5}
                    />
                    <text
                      y={r + 11}
                      textAnchor="middle"
                      fontSize="10"
                      fill="var(--color-fg)"
                      direction="ltr"
                    >
                      {n.label.length > 18 ? `${n.label.slice(0, 17)}…` : n.label}
                    </text>
                    <title>
                      {`${n.label}\n${labels.risk}: ${labels.riskLevels[n.risk.level]} (${n.risk.score})\n${n.ipAddresses.join(', ')}`}
                    </title>
                  </g>
                );
              })}
          </svg>
        </div>
      </section>

      <aside
        className="rounded-lg border border-border bg-surface p-4 text-sm"
        data-testid="asset-panel"
      >
        {!selected ? (
          <p className="text-muted">{labels.selectHint}</p>
        ) : loading ? (
          <p className="text-muted">{labels.loading}</p>
        ) : error ? (
          <p className="text-sev-critical" role="alert">
            {error}
          </p>
        ) : profile ? (
          <ProfilePanel profile={profile} labels={labels} onSelect={setSelected} />
        ) : null}
      </aside>
    </div>
  );
}

function ProfilePanel({
  profile: p,
  labels,
  onSelect,
}: {
  profile: AssetRiskProfile;
  labels: GraphLabels;
  onSelect: (id: string) => void;
}) {
  const h2 = 'mt-4 text-xs font-medium uppercase tracking-wide text-muted';
  return (
    <div className="space-y-1">
      <h2 className="ltr text-lg font-semibold" data-testid="panel-title">
        {p.asset.hostname ?? p.asset.ipAddresses[0] ?? p.asset.id.slice(0, 8)}
      </h2>
      <p className="ltr text-xs text-muted">
        {p.asset.assetClass} · {p.site ?? '—'} · {p.asset.ipAddresses.join(', ') || '—'}
      </p>
      <p className="text-xs text-muted">
        {p.asset.monitoringCoverage} · {p.asset.assuranceState}
      </p>
      <p className="mt-2">
        <span className="font-medium">{labels.risk}: </span>
        <span
          style={{ color: RISK_COLOR[p.risk.level] }}
          className="font-semibold"
          data-testid="panel-risk"
        >
          {labels.riskLevels[p.risk.level]}
        </span>
        <span className="ltr ms-2 text-xs text-muted">
          {labels.score} {p.risk.score}/100 · {labels.confidence} {p.risk.confidence}
        </span>
      </p>
      <p className={h2}>{labels.basis}</p>
      <ul className="list-disc ps-4 text-xs">
        {p.risk.basis.map((b, i) => (
          <li key={i}>{b}</li>
        ))}
      </ul>

      <p className={h2}>{labels.ports}</p>
      {p.openPorts.length === 0 ? (
        <p className="text-xs text-muted">{labels.noPorts}</p>
      ) : (
        <ul className="ltr space-y-0.5 text-xs">
          {p.openPorts.map((o) => (
            <li key={`${o.proto}/${o.port}`} className="flex flex-wrap gap-x-2">
              <span className="font-mono">
                {o.proto}/{o.port}
              </span>
              {o.service ? (
                <span className={SEV_CLASS[o.severity ?? 'info']}>{o.service}</span>
              ) : null}
              {o.why ? <span className="text-muted">{o.why}</span> : null}
              <span className="text-muted">
                [{labels.source}: {o.source}]
              </span>
            </li>
          ))}
        </ul>
      )}

      <p className={h2}>{labels.techniques}</p>
      {p.techniques.length === 0 ? (
        <p className="text-xs text-muted">{labels.noTechniques}</p>
      ) : (
        <ul className="space-y-0.5 text-xs">
          {p.techniques.map((t) => (
            <li key={`${t.source}:${t.techniqueId}`} className="ltr flex flex-wrap gap-x-2">
              <span className="font-mono">{t.techniqueId}</span>
              <span>{t.name ?? '—'}</span>
              {t.tactic ? <span className="text-muted">({t.tactic})</span> : null}
              <span className={t.source === 'alert' ? 'text-sev-high' : 'text-sev-medium'}>
                {t.source === 'alert' ? labels.techAlert : labels.techExposure}
                {t.count > 1 ? ` ×${t.count}` : ''}
              </span>
              <span className="text-muted">{t.evidence}</span>
            </li>
          ))}
        </ul>
      )}

      <p className={h2}>{labels.findings}</p>
      {!p.findingsIncluded ? (
        <p className="text-xs text-muted">{labels.findingsWithheld}</p>
      ) : p.findings.length === 0 ? (
        <p className="text-xs text-muted">{labels.noFindings}</p>
      ) : (
        <ul className="space-y-0.5 text-xs">
          {p.findings.map((f) => (
            <li key={f.id} className="ltr">
              <span className={SEV_CLASS[f.severity]}>{f.severity}</span> {f.title}
              {f.cve.length ? <span className="text-muted"> · {f.cve.join(', ')}</span> : null}
              {f.cwe.length ? <span className="text-muted"> · {f.cwe.join(', ')}</span> : null}
              <span className="text-muted">
                {' '}
                · {f.status}
                {f.validated ? '' : ' · unvalidated'}
              </span>
            </li>
          ))}
        </ul>
      )}

      <p className={h2}>{labels.alerts}</p>
      {!p.alertsIncluded ? (
        <p className="text-xs text-muted">{labels.alertsWithheld}</p>
      ) : p.alerts.length === 0 ? (
        <p className="text-xs text-muted">{labels.noAlerts}</p>
      ) : (
        <ul className="space-y-0.5 text-xs">
          {p.alerts.slice(0, 10).map((a) => (
            <li key={a.id} className="ltr">
              <span className={SEV_CLASS[a.severity]}>{a.severity}</span> {a.title}
              <span className="text-muted">
                {' '}
                · {a.status} ×{a.occurrenceCount}
                {a.techniques.length ? ` · ${a.techniques.join(', ')}` : ''}
              </span>
            </li>
          ))}
        </ul>
      )}

      <p className={h2}>{labels.neighbors}</p>
      {p.neighbors.length === 0 ? (
        <p className="text-xs text-muted">{labels.noNeighbors}</p>
      ) : (
        <ul className="space-y-0.5 text-xs">
          {p.neighbors.map((n) => (
            <li key={`${n.basis}:${n.assetId}:${n.kind}`} className="ltr">
              <button
                type="button"
                className="underline hover:text-accent"
                onClick={() => onSelect(n.assetId)}
              >
                {n.label}
              </button>
              <span className="text-muted">
                {' '}
                · {n.kind} · {n.direction} ·{' '}
                {n.basis === 'topology'
                  ? labels.legendTopology
                  : `${labels.legendTraffic} ×${n.weight}`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
