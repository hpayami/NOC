import { notFound } from 'next/navigation';
import { z } from 'zod';
import { AssessmentRun, EngagementRecord, FindingRecord, TechniqueInfo } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { ApiError, apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { DecisionForm, NewRunForm, RunButton, TransitionForm } from '../controls';
import { ENG_STATUS_LABEL, ENG_STATUS_STYLE, transitionTargets } from '../labels';

export const dynamic = 'force-dynamic';
const Runs = z.object({ items: z.array(AssessmentRun) });
const Findings = z.object({ items: z.array(FindingRecord) });
const Techniques = z.object({ items: z.array(TechniqueInfo) });

export default async function EngagementPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const perms = new Set(me?.permissions ?? []);
  let e: EngagementRecord;
  try {
    e = await apiFetch(`/api/v1/assessments/engagements/${id}`, EngagementRecord);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  const [runs, findings, techniques] = await Promise.all([
    apiFetch(`/api/v1/assessments/engagements/${id}/runs`, Runs),
    perms.has('findings.read')
      ? apiFetch(`/api/v1/findings?engagementId=${id}&limit=200`, Findings)
      : Promise.resolve({ items: [] as FindingRecord[] }),
    apiFetch('/api/v1/assessments/techniques', Techniques),
  ]);
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });
  const states = Object.fromEntries(
    (Object.keys(ENG_STATUS_LABEL) as Array<keyof typeof ENG_STATUS_LABEL>).map((s) => [
      s,
      t(ENG_STATUS_LABEL[s]),
    ]),
  );
  const allowedTechniques = techniques.items.filter((x) =>
    e.scope.allowedTechniques.includes(x.technique),
  );

  return (
    <div className="space-y-6">
      <a href="/red-team" className="text-xs text-muted hover:text-fg">
        ← {t('eng.back')}
      </a>
      <header>
        <h1 className="ltr text-2xl font-semibold">{e.reference}</h1>
        <p className="mt-1 text-sm text-muted">
          <span className={`font-medium ${ENG_STATUS_STYLE[e.status]}`} data-testid="eng-status">
            {states[e.status]}
          </span>
          <span className="mx-2">·</span>
          {e.authorizingOrganization}
          <span className="mx-2">·</span>
          <span className="ltr">{e.authorizationReference}</span>
          <span className="mx-2">·</span>
          {t('eng.scope')} v{e.scopeVersion}
          {e.approvedScopeVersion === e.scopeVersion
            ? ` (${t('eng.status.approved')})`
            : ` (${t('eng.unapproved_scope')})`}
        </p>
        <p className="mt-2 max-w-3xl text-sm">{e.objective}</p>
        {e.closeReason ? <p className="mt-1 text-xs text-muted">{e.closeReason}</p> : null}
      </header>

      <section className="grid gap-4 rounded-lg border border-border bg-surface p-4 text-xs md:grid-cols-2">
        <div>
          <p className="text-muted">
            {t('eng.include_cidrs')} / {t('eng.include_addresses')}
          </p>
          <p className="ltr">
            {[...e.scope.includeCidrs, ...e.scope.includeAddresses].join(', ') || '—'}
          </p>
          <p className="mt-1 text-muted">{t('eng.exclude_cidrs')}</p>
          <p className="ltr">
            {[...e.scope.excludeCidrs, ...e.scope.excludeAddresses].join(', ') || '—'}
          </p>
          <p className="mt-1 text-muted">{t('eng.techniques')}</p>
          <p className="ltr">{e.scope.allowedTechniques.join(', ')}</p>
        </div>
        <div>
          <p className="text-muted">{t('eng.window')}</p>
          <p>
            {when.format(new Date(e.scope.windowStart))} →{' '}
            {when.format(new Date(e.scope.windowEnd))}
          </p>
          <p className="mt-1 text-muted">{t('eng.stop_conditions')}</p>
          <ul className="list-disc ps-4">
            {e.stopConditions.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
          <p className="mt-1 text-muted">
            {t('eng.emergency_contact')}: <span className="ltr">{e.emergencyContact}</span>
          </p>
          {e.approvals.length ? (
            <ul className="mt-1 text-muted">
              {e.approvals.map((a, i) => (
                <li key={i} className="ltr">
                  {a.decision} v{a.scopeVersion} · {a.approverId.slice(0, 8)} · {a.justification}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </section>

      <section className="flex flex-wrap items-center gap-3">
        <a
          href={`/red-team/${e.id}/report`}
          className="rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
        >
          {t('eng.report')}
        </a>
        <TransitionForm
          id={e.id}
          targets={transitionTargets(e.status, perms)}
          labels={{ reason: t('inc.reason'), states }}
        />
        {e.status === 'pending_approval' && perms.has('assessments.approve') ? (
          <DecisionForm
            id={e.id}
            labels={{
              approve: t('resp.approve'),
              reject: t('resp.reject'),
              justification: t('resp.decision_note'),
            }}
          />
        ) : null}
      </section>

      <section className="space-y-3" aria-labelledby="runs">
        <h2 id="runs" className="font-medium">
          {t('eng.runs')}
        </h2>
        {e.status === 'active' && perms.has('assessments.execute') ? (
          <NewRunForm
            id={e.id}
            techniques={allowedTechniques}
            labels={{
              technique: t('eng.technique'),
              ports: t('eng.ports'),
              dryRun: t('eng.dry_run'),
              submit: t('eng.queue_run'),
            }}
          />
        ) : null}
        {runs.items.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-4 text-xs text-muted">
            {t('eng.no_runs')}
          </p>
        ) : (
          <ul className="space-y-2">
            {runs.items.map((r) => (
              <li
                key={r.id}
                className="rounded-lg border border-border bg-surface px-4 py-3 text-xs"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="ltr font-medium">{r.technique}</span>
                  <span className="ltr">{r.dryRun ? 'dry run' : 'live'}</span>
                  <span className="ltr">{r.status}</span>
                  <span className="ltr text-muted">
                    targets {r.targetCount} · ports {r.ports.join(',')}
                  </span>
                  <span className="ms-auto text-muted">{when.format(new Date(r.createdAt))}</span>
                </div>
                {r.summary ? (
                  <p className="ltr mt-1 text-muted">
                    allowed {r.summary.allowed} · denied {r.summary.denied} · reachable{' '}
                    {r.summary.reachable} · unreachable {r.summary.unreachable} · skipped{' '}
                    {r.summary.skipped} · findings +{r.summary.findingsCreated}/~
                    {r.summary.findingsUpdated}
                  </p>
                ) : null}
                <div className="mt-1 flex gap-2">
                  {r.status === 'queued' && perms.has('assessments.execute') ? (
                    <RunButton id={e.id} runId={r.id} op="execute" label={t('eng.execute')} />
                  ) : null}
                  {(r.status === 'queued' || r.status === 'running') &&
                  (perms.has('assessments.execute') || perms.has('assessments.approve')) ? (
                    <RunButton id={e.id} runId={r.id} op="cancel" label={t('eng.cancel_run')} />
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-3" aria-labelledby="findings">
        <h2 id="findings" className="font-medium">
          {t('eng.findings')}
        </h2>
        {findings.items.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-4 text-xs text-muted">
            {t('eng.no_findings')}
          </p>
        ) : (
          <ul className="space-y-2">
            {findings.items.map((f) => (
              <li
                key={f.id}
                className="rounded-lg border border-border bg-surface px-4 py-3 text-xs"
              >
                <span className="ltr font-medium">{f.title}</span> ·{' '}
                <span className="ltr">{f.severity}</span> · <span className="ltr">{f.status}</span>
                <p className="mt-1 text-muted">{f.description}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
