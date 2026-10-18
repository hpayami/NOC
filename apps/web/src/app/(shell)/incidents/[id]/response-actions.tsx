import { z } from 'zod';
import {
  ResponseActionRecord,
  ResponseExecutorInfo,
  type ResponseActionKind,
  type ResponseActionStatus,
} from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { apiFetch } from '@/lib/api';
import { DecisionForm, ProposeForm, RunForm } from './response-controls';

const List = z.object({ items: z.array(ResponseActionRecord), nextCursor: z.string().nullable() });
const Catalog = z.object({ items: z.array(ResponseExecutorInfo) });

const STATUS_STYLE: Record<ResponseActionStatus, string> = {
  recommended: 'text-muted',
  pending_approval: 'text-sev-medium',
  approved: 'text-sev-low',
  rejected: 'text-muted',
  executing: 'text-sev-medium',
  executed: 'text-ok',
  verification_failed: 'text-sev-high',
  rolled_back: 'text-muted',
  expired: 'text-muted',
  failed: 'text-sev-critical',
};

/** Response actions attached to an incident: propose / decide / execute / roll back by permission. */
export async function ResponseActionsSection({
  incidentId,
  closed,
  permissions,
}: {
  incidentId: string;
  closed: boolean;
  permissions: ReadonlySet<string>;
}) {
  const { t, locale } = await getI18n();
  if (!permissions.has('response.read')) return null;
  const [list, catalog] = await Promise.all([
    apiFetch(`/api/v1/response-actions?incidentId=${incidentId}&limit=50`, List),
    apiFetch('/api/v1/response-actions/executors', Catalog),
  ]);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const kindLabel = (k: ResponseActionKind) => t(`resp.kind.${k}` as MessageKey);
  const canPropose = permissions.has('response.propose') && !closed;
  const kinds = catalog.items
    .filter((e) => e.kind !== 'enable_inline_prevention' || permissions.has('ips.propose'))
    .map((e) => ({
      kind: e.kind,
      label: kindLabel(e.kind),
      available: e.available,
      approvals: e.requiredApprovals,
    }));

  return (
    <section className="space-y-3" aria-labelledby="response">
      <h2 id="response" className="font-medium">
        {t('resp.title')}
      </h2>
      <p className="text-xs text-muted">{t('resp.subtitle')}</p>
      {list.items.length === 0 ? (
        <p className="rounded-lg border border-border bg-surface p-4 text-xs text-muted">
          {t('resp.empty')}
        </p>
      ) : (
        <ul className="space-y-2">
          {list.items.map((a) => (
            <li
              key={a.id}
              className="rounded-lg border border-border bg-surface px-4 py-3 text-sm"
              data-testid="response-action"
            >
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="ltr font-medium">{a.kind}</span>
                <span className="text-muted">{kindLabel(a.kind)}</span>
                <span className="ltr text-muted">
                  {a.targetType}:{a.targetRef}
                </span>
                <span
                  className={`ltr font-medium ${STATUS_STYLE[a.status]}`}
                  data-testid="response-status"
                >
                  {t(`resp.status.${a.status}` as MessageKey)}
                </span>
                <span className="ltr text-muted">
                  {a.approvalsGranted}/{a.requiredApprovals}✓
                </span>
                {!a.executorAvailable ? (
                  <span className="rounded border border-sev-medium/30 px-1 text-sev-medium">
                    {t('resp.executor_unavailable')}
                  </span>
                ) : null}
                <span className="ms-auto text-muted">{when.format(new Date(a.createdAt))}</span>
              </div>
              <p className="mt-1 text-xs">{a.justification}</p>
              <p className="mt-1 text-[11px] text-muted">
                {t('resp.rollback_plan')}: {a.rollbackPlan}
              </p>
              {a.approvals.length ? (
                <ul className="mt-1 text-[11px] text-muted">
                  {a.approvals.map((p, i) => (
                    <li key={i} className="ltr">
                      {p.decision} · {p.approverId.slice(0, 8)} · {p.justification}
                    </li>
                  ))}
                </ul>
              ) : null}
              {a.status === 'executed' && typeof a.result.count === 'number' ? (
                <p className="ltr mt-1 text-[11px] text-muted">evidence: {a.result.count}</p>
              ) : null}
              {a.status === 'pending_approval' && permissions.has('response.approve') ? (
                <DecisionForm
                  actionId={a.id}
                  labels={{
                    approve: t('resp.approve'),
                    reject: t('resp.reject'),
                    justification: t('resp.decision_note'),
                  }}
                />
              ) : null}
              {a.status === 'approved' &&
              a.executorAvailable &&
              permissions.has('response.execute') ? (
                <RunForm actionId={a.id} op="execute" label={t('resp.execute')} />
              ) : null}
              {(a.status === 'executed' || a.status === 'verification_failed') &&
              permissions.has('response.rollback') ? (
                <RunForm actionId={a.id} op="rollback" label={t('resp.rollback')} />
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {canPropose ? (
        <ProposeForm
          incidentId={incidentId}
          kinds={kinds}
          labels={{
            heading: t('resp.propose'),
            kind: t('resp.kind'),
            targetType: t('resp.target_type'),
            target: t('resp.target'),
            justification: t('resp.justification'),
            rollbackPlan: t('resp.rollback_plan'),
            submit: t('resp.submit'),
          }}
        />
      ) : null}
    </section>
  );
}
