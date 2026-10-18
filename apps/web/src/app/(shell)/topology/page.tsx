import { z } from 'zod';
import { NetworkSegment, TopologyGraph } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { apiFetch } from '@/lib/api';

export const dynamic = 'force-dynamic';

export default async function TopologyPage() {
  const { t, locale } = await getI18n();
  const [graph, segments] = await Promise.all([
    apiFetch('/api/v1/network/topology', TopologyGraph),
    apiFetch('/api/v1/network/segments', z.array(NetworkSegment)),
  ]);
  const fmt = new Intl.NumberFormat(locale === 'fa' ? 'fa-IR' : 'en-US');
  const label = new Map(graph.nodes.map((n) => [n.id, n.label]));
  const verified = graph.edges.filter((e) => e.verification === 'verified').length;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('topology.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('topology.subtitle')}</p>
        <p className="mt-2 text-xs text-muted">
          {t('topology.nodes')}: {fmt.format(graph.nodes.length)} · {t('topology.edges')}:{' '}
          {fmt.format(graph.edges.length)} ({t('topology.verified')}: {fmt.format(verified)},{' '}
          {t('topology.inferred')}: {fmt.format(graph.edges.length - verified)})
          {graph.truncated ? ` · ${t('topology.truncated')}` : ''}
        </p>
      </header>

      <section aria-labelledby="segments">
        <h2 id="segments" className="mb-3 text-lg font-medium">
          {t('topology.segments')}
        </h2>
        {segments.length === 0 ? (
          <p className="text-sm text-muted">{t('topology.no_segments')}</p>
        ) : (
          <ul className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {segments.map((s) => (
              <li key={s.id} className="rounded-lg border border-border bg-surface p-3 text-sm">
                <p className="font-medium">{s.name}</p>
                <p className="ltr text-xs text-muted">
                  {s.cidr ?? '—'}
                  {s.vlanId ? ` · VLAN ${s.vlanId}` : ''}
                  {s.site ? ` · ${s.site}` : ''}
                </p>
                <p
                  className={`mt-1 text-xs ${s.activeDiscoveryAllowed ? 'text-sev-medium' : 'text-muted'}`}
                >
                  {s.activeDiscoveryAllowed
                    ? t('topology.active_allowed')
                    : t('topology.active_denied')}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="edges">
        <h2 id="edges" className="mb-3 text-lg font-medium">
          {t('topology.relationships')}
        </h2>
        {graph.edges.length === 0 ? (
          <div className="rounded-lg border border-border bg-surface p-4 text-sm">
            <p>{t('topology.no_edges')}</p>
            <p className="mt-1 text-xs text-muted">{t('topology.no_edges_hint')}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead className="bg-surface text-xs text-muted">
                <tr>
                  <th className="px-3 py-2 text-start">{t('topology.source')}</th>
                  <th className="px-3 py-2 text-start">{t('topology.target')}</th>
                  <th className="px-3 py-2 text-start">{t('topology.kind')}</th>
                  <th className="px-3 py-2 text-start">{t('topology.verification')}</th>
                  <th className="px-3 py-2 text-start">{t('topology.evidence')}</th>
                </tr>
              </thead>
              <tbody>
                {graph.edges.map((e) => (
                  <tr key={e.id} className="border-t border-border align-top">
                    <td className="ltr px-3 py-2 text-xs">
                      {label.get(e.sourceAssetId) ?? e.sourceAssetId.slice(0, 8)}
                    </td>
                    <td className="ltr px-3 py-2 text-xs">
                      {label.get(e.targetAssetId) ?? e.targetAssetId.slice(0, 8)}
                    </td>
                    <td className="ltr px-3 py-2 text-xs">{e.kind}</td>
                    <td
                      className={`px-3 py-2 text-xs ${e.verification === 'verified' ? 'text-ok' : 'text-sev-medium'}`}
                    >
                      {e.verification === 'verified'
                        ? t('topology.verified')
                        : t('topology.inferred')}
                    </td>
                    <td className="ltr px-3 py-2 text-xs text-muted">{e.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
