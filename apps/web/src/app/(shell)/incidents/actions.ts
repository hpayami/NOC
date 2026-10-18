'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import {
  CreateIncidentRequest,
  IncidentNoteRequest,
  IncidentSummary,
  IncidentTimelineEntry,
  IncidentTransitionRequest,
  IncidentUpdateRequest,
} from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';

export type ActionState = { error: string } | null;
const UUID = /^[0-9a-f-]{36}$/;
const fail = (e: unknown): ActionState => {
  if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
  throw e;
};

export async function createIncident(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const alertIds = formData
    .getAll('alertId')
    .map(String)
    .filter((id) => UUID.test(id));
  const parsed = CreateIncidentRequest.safeParse({
    title: formData.get('title'),
    type: formData.get('type') ?? undefined,
    severity: formData.get('severity'),
    summary: String(formData.get('summary') ?? ''),
    alertIds,
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  let id: string;
  try {
    id = (
      await apiFetch('/api/v1/incidents', IncidentSummary, {
        method: 'POST',
        body: JSON.stringify(parsed.data),
      })
    ).id;
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/incidents');
  revalidatePath('/soc-alerts');
  redirect(`/incidents/${id}`);
}

/** Bound from the alert queue: one click opens an incident carrying that alert. */
export async function openIncidentFromAlert(
  alert: { id: string; title: string; severity: string },
  _formData: FormData,
): Promise<void> {
  const fd = new FormData();
  fd.set('title', alert.title);
  fd.set('severity', alert.severity);
  fd.append('alertId', alert.id);
  const r = await createIncident(null, fd);
  if (r?.error) redirect(`/soc-alerts?error=${encodeURIComponent(r.error)}`);
}

export async function transitionIncident(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid incident id' };
  const reason = String(formData.get('reason') ?? '').trim();
  const parsed = IncidentTransitionRequest.safeParse({
    to: formData.get('to'),
    ...(reason ? { reason } : {}),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/incidents/${id}/transition`, IncidentSummary, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath(`/incidents/${id}`);
  revalidatePath('/incidents');
  return null;
}

export async function addIncidentNote(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid incident id' };
  const parsed = IncidentNoteRequest.safeParse({ note: formData.get('note') });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/incidents/${id}/notes`, IncidentTimelineEntry, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath(`/incidents/${id}`);
  return null;
}

export async function assignIncidentToMe(id: string, _formData: FormData): Promise<void> {
  if (!UUID.test(id)) return;
  const me = await getSessionUser();
  if (!me) redirect('/login?reason=expired');
  const body = IncidentUpdateRequest.parse({ assigneeId: me.id });
  try {
    await apiFetch(`/api/v1/incidents/${id}`, IncidentSummary, {
      method: 'PATCH',
      body: JSON.stringify(body),
    });
  } catch (e) {
    if (!(e instanceof ApiError)) throw e;
  }
  revalidatePath(`/incidents/${id}`);
}
