import { notFound } from 'next/navigation';
import { IncidentDetail, type IncidentTimelineKind } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import type { MessageKey } from '@/i18n/messages';
import { ApiError, apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { assignIncidentToMe } from '../actions';
import { SEV_STYLE, STATUS_LABEL } from '../labels';
import { NoteForm, TransitionControls } from './controls';

export const dynamic = 'force-dynamic';

const KIND_LABEL: Record<IncidentTimelineKind, MessageKey> = {
  opened: 'inc.kind.opened',
  transition: 'inc.kind.transition',
  note: 'inc.kind.note',
  assignment: 'inc.kind.assignment',
  severity_changed: 'inc.kind.severity_changed',
  updated: 'inc.kind.updated',
  alert_linked: 'inc.kind.alert_linked',
  alert_unlinked: 'inc.kind.alert_unlinked',
};

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const canManage = me?.permissions.includes('incidents.manage') ?? false;
  const canClose = me?.permissions.includes('incidents.close') ?? false;
  let detail: IncidentDetail;
  try {
    detail = await apiFetch(`/api/v1/incidents/${id}`, IncidentDetail);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
  const { incident, alerts, timeline } = detail;
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'medium',
  });
  const states = Object.fromEntries(
    (Object.keys(STATUS_LABEL) as Array<keyof typeof STATUS_LABEL>).map((s) => [
      s,
      t(STATUS_LABEL[s]),
    ]),
  ) as Record<keyof typeof STATUS_LABEL, string>;
  const closed = incident.status === 'closed';

  return (
    <div className="space-y-6">
      <a href="/incidents" className="text-xs text-muted hover:text-fg">
        ← {t('inc.back')}
      </a>
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{incident.title}</h1>
          <p className="mt-1 text-sm text-muted">
            <span className={`ltr font-medium ${SEV_STYLE[incident.severity]}`}>
              {incident.severity}
            </span>
            <span className="mx-2">·</span>
            {t(`inc.type.${incident.type}` as MessageKey)}
            <span className="mx-2">·</span>
            <span data-testid="incident-status">{states[incident.status]}</span>
            <span className="mx-2">·</span>
            {t('inc.opened')} {when.format(new Date(incident.openedAt))}
          </p>
          {incident.summary ? <p className="mt-2 max-w-2xl text-sm">{incident.summary}</p> : null}
          {closed ? (
            <p className="mt-2 text-xs text-muted">
              {t('inc.closed_readonly')}
              {incident.closureReason ? ` — ${incident.closureReason}` : ''}
            </p>
          ) : null}
        </div>
        {canManage && !closed && incident.assigneeId !== me?.id ? (
          <form action={assignIncidentToMe.bind(null, incident.id)}>
            <button
              type="submit"
              className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
            >
              {t('inc.assign_me')}
            </button>
          </form>
        ) : null}
      </header>

      <div className="grid gap-6 lg:grid-cols-3">
        <section className="space-y-4 lg:col-span-2" aria-labelledby="timeline">
          <h2 id="timeline" className="font-medium">
            {t('inc.timeline')}
          </h2>
          <ol className="space-y-2">
            {timeline.map((e) => (
              <li
                key={e.id}
                className="rounded-lg border border-border bg-surface px-4 py-3 text-sm"
              >
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
                  <span className="font-medium text-fg">{t(KIND_LABEL[e.kind])}</span>
                  {e.toStatus ? (
                    <span>
                      {e.fromStatus ? `${states[e.fromStatus]} → ` : ''}
                      {states[e.toStatus]}
                    </span>
                  ) : null}
                  {e.payload.deviation === true ? (
                    <span className="rounded border border-sev-medium/30 px-1 text-sev-medium">
                      {t('inc.deviation')}
                    </span>
                  ) : null}
                  <span className="ms-auto">{when.format(new Date(e.occurredAt))}</span>
                </div>
                {e.note ? <p className="mt-1 whitespace-pre-wrap">{e.note}</p> : null}
                {e.kind === 'alert_linked' || e.kind === 'alert_unlinked' ? (
                  <p className="ltr mt-1 text-xs text-muted">{String(e.payload.title ?? '')}</p>
                ) : null}
              </li>
            ))}
          </ol>
          {canManage && !closed ? (
            <NoteForm
              id={incident.id}
              labels={{ note: t('inc.note'), submit: t('inc.add_note') }}
            />
          ) : null}
        </section>

        <aside className="space-y-4">
          {canManage ? (
            <TransitionControls
              id={incident.id}
              allowedNext={incident.allowedNext}
              canClose={canClose}
              labels={{ heading: t('inc.transition'), reason: t('inc.reason'), states }}
            />
          ) : null}
          <section
            className="rounded-lg border border-border bg-surface p-4"
            aria-labelledby="linked"
          >
            <h2 id="linked" className="text-sm font-medium">
              {t('inc.linked_alerts')}
            </h2>
            {alerts.length === 0 ? (
              <p className="mt-2 text-xs text-muted">{t('inc.no_alerts')}</p>
            ) : (
              <ul className="mt-2 space-y-2 text-xs">
                {alerts.map((a) => (
                  <li
                    key={a.id}
                    className="border-t border-border pt-2 first:border-t-0 first:pt-0"
                  >
                    <span className="ltr block">{a.title}</span>
                    <span className="ltr block text-[10px] text-muted">
                      <span className={SEV_STYLE[a.severity]}>{a.severity}</span> · {a.status} ·{' '}
                      {a.sourceProduct} · ×{a.occurrenceCount}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </div>
    </div>
  );
}
