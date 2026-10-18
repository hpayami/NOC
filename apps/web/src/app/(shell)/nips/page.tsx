import { z } from 'zod';
import { IpsPolicy, PlatformStatus, SensorStatus, type IpsPolicyStatus } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { CapabilityBadge } from '@/components/status-badges';
import { DecisionForm, DisableForm, EnableForm, ProposePolicyForm } from './controls';

export const dynamic = 'force-dynamic';
const List = z.object({ items: z.array(IpsPolicy) });

const STATUS_STYLE: Record<IpsPolicyStatus, string> = {
  pending_approval: 'text-sev-medium',
  approved: 'text-sev-low',
  enabled: 'text-sev-high',
  disabled: 'text-muted',
  rejected: 'text-muted',
  expired: 'text-muted',
};

export default async function NipsPage() {
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const perms = new Set(me?.permissions ?? []);
  const [policies, status, sensors] = await Promise.all([
    apiFetch('/api/v1/ips/policies?limit=100', List),
    apiFetch('/api/v1/platform/status', PlatformStatus),
    perms.has('sensors.read')
      ? apiFetch('/api/v1/sensors', z.array(SensorStatus))
      : Promise.resolve([]),
  ]);
  const cap = status.capabilities.find((c) => c.id === 'nips.inline_prevention');
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const capLabel: Record<string, MessageKey> = {
    available: 'cap.available',
    degraded: 'cap.degraded',
    disabled: 'cap.disabled',
    not_configured: 'cap.not_configured',
    not_implemented: 'cap.not_implemented',
  };
  const suricata = sensors
    .filter((s) => s.sensor.kind === 'suricata')
    .map((s) => ({ id: s.sensor.id, name: s.sensor.name, inlineCapable: s.sensor.inlineCapable }));

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">{t('nips.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('nips.subtitle')}</p>
      </header>

      <section className="rounded-lg border border-border bg-surface p-5" aria-labelledby="state">
        <h2 id="state" className="text-sm font-medium">
          {t('nips.state')}
        </h2>
        {cap ? (
          <p className="mt-2 flex flex-wrap items-center gap-3 text-sm">
            <span className="ltr text-xs">{cap.id}</span>
            <CapabilityBadge
              state={cap.state}
              label={t(capLabel[cap.state] ?? 'cap.not_implemented')}
            />
            <span className="text-xs text-muted" data-testid="nips-reason">
              {cap.reason}
            </span>
          </p>
        ) : null}
        <p className="mt-2 text-xs text-muted">{t('nips.invariant')}</p>
      </section>

      <section className="space-y-3" aria-labelledby="policies">
        <h2 id="policies" className="font-medium">
          {t('nips.policies')}
        </h2>
        {policies.items.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-5 text-sm">
            {t('nips.empty')}
          </p>
        ) : (
          <ul className="space-y-2">
            {policies.items.map((p) => (
              <li
                key={p.id}
                className="rounded-lg border border-border bg-surface px-4 py-3 text-sm"
                data-testid="ips-policy"
              >
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium">{p.name}</span>
                  <span className="ltr text-muted">{p.sensorName}</span>
                  <span className="ltr">
                    {p.mode}/{p.action}
                  </span>
                  <span
                    className={`ltr font-medium ${STATUS_STYLE[p.status]}`}
                    data-testid="ips-status"
                  >
                    {t(`nips.status.${p.status}` as MessageKey)}
                  </span>
                  <span className="ltr text-muted">
                    {p.approvalsGranted}/{p.requiredApprovals}✓ · v{p.version} · {t('nips.apply')}{' '}
                    {p.applyState}
                    {p.appliedVersion !== null ? ` v${p.appliedVersion}` : ''}
                  </span>
                  {p.expiresAt && p.status === 'enabled' ? (
                    <span className="text-sev-high">
                      {t('nips.expires')} {when.format(new Date(p.expiresAt))}
                    </span>
                  ) : null}
                </div>
                <p className="ltr mt-1 text-[11px] text-muted">
                  protected {p.protectedCidrs.join(', ')}
                  {p.excludedCidrs.length ? ` · excluded ${p.excludedCidrs.join(', ')}` : ''} ·
                  rules {p.ruleIds.length}
                </p>
                <p className="mt-1 text-xs">{p.justification}</p>
                <p className="mt-1 text-[11px] text-muted">
                  {t('nips.rollback_plan')}: {p.rollbackPlan}
                </p>
                {p.disableReason ? (
                  <p className="mt-1 text-[11px] text-muted">
                    {t('nips.disabled_reason')}: {p.disableReason}
                  </p>
                ) : null}
                {p.status === 'pending_approval' && perms.has('ips.approve') ? (
                  <DecisionForm
                    id={p.id}
                    labels={{
                      approve: t('resp.approve'),
                      reject: t('resp.reject'),
                      justification: t('resp.decision_note'),
                    }}
                  />
                ) : null}
                {p.status === 'approved' && perms.has('ips.enable') ? (
                  <EnableForm
                    id={p.id}
                    labels={{ hours: t('nips.hours'), enable: t('nips.enable') }}
                  />
                ) : null}
                {p.status === 'enabled' && (perms.has('ips.enable') || perms.has('ips.approve')) ? (
                  <DisableForm
                    id={p.id}
                    labels={{ reason: t('nips.disable_reason'), disable: t('nips.disable') }}
                  />
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      {perms.has('ips.propose') ? (
        <ProposePolicyForm
          sensors={suricata}
          labels={{
            heading: t('nips.propose'),
            name: t('inc.new_title'),
            sensor: t('nips.sensor'),
            mode: t('nips.mode'),
            protected: t('nips.protected'),
            excluded: t('nips.excluded'),
            rules: t('nips.rules'),
            justification: t('resp.justification'),
            rollbackPlan: t('nips.rollback_plan'),
            submit: t('resp.submit'),
            noSensors: t('nips.no_sensors'),
          }}
        />
      ) : null}
    </div>
  );
}
