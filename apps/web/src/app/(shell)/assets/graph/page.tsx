import { AssetGraph } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';
import { AssetGraphView, type GraphLabels } from './graph-view';

export const dynamic = 'force-dynamic';

export default async function AssetGraphPage({
  searchParams,
}: {
  searchParams: Promise<{ hours?: string }>;
}) {
  const { t, locale } = await getI18n();
  const { hours } = await searchParams;
  const h = Math.min(720, Math.max(1, Number(hours) || 168));
  const graph = await apiFetch(`/api/v1/assets/graph?hours=${h}&limit=500`, AssetGraph);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const labels: GraphLabels = {
    search: t('graph.search'),
    filterRisk: t('graph.filter_risk'),
    filterSite: t('graph.filter_site'),
    all: t('graph.all'),
    legendTopology: t('graph.legend_topology'),
    legendTraffic: t('graph.legend_traffic'),
    selectHint: t('graph.select_hint'),
    loading: t('graph.loading'),
    risk: t('graph.risk'),
    score: t('graph.score'),
    confidence: t('graph.confidence'),
    basis: t('graph.basis'),
    ports: t('graph.ports'),
    noPorts: t('graph.no_ports'),
    techniques: t('graph.techniques'),
    techAlert: t('graph.tech_alert'),
    techExposure: t('graph.tech_exposure'),
    noTechniques: t('graph.no_techniques'),
    findings: t('graph.findings'),
    findingsWithheld: t('graph.findings_withheld'),
    noFindings: t('graph.no_findings'),
    alerts: t('graph.alerts'),
    alertsWithheld: t('graph.alerts_withheld'),
    noAlerts: t('graph.no_alerts'),
    neighbors: t('graph.neighbors'),
    noNeighbors: t('graph.no_neighbors'),
    source: t('graph.source'),
    noEdges: t('graph.no_edges'),
    riskLevels: {
      critical: t('graph.risk.critical'),
      high: t('graph.risk.high'),
      medium: t('graph.risk.medium'),
      low: t('graph.risk.low'),
      none: t('graph.risk.none'),
      unknown: t('graph.risk.unknown'),
    },
  };

  return (
    <div className="space-y-4">
      <a href="/assets" className="text-xs text-muted hover:text-fg">
        ← {t('graph.back')}
      </a>
      <header>
        <h1 className="text-2xl font-semibold">{t('graph.title')}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted">{t('graph.subtitle')}</p>
        <p className="mt-2 text-xs text-muted">
          {t('graph.nodes')}: {fmt.format(graph.nodes.length)} · {t('graph.edges')}:{' '}
          {fmt.format(graph.edges.length)} · {t('graph.window')}: {fmt.format(h)} {t('graph.hours')}
          {graph.truncated ? ` · ${t('graph.truncated')}` : ''}
        </p>
      </header>
      {graph.nodes.length === 0 ? (
        <p className="rounded-lg border border-border bg-surface p-6 text-sm text-muted">
          {t('graph.empty')}
        </p>
      ) : (
        <AssetGraphView graph={graph} labels={labels} />
      )}
    </div>
  );
}
