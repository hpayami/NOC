'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import {
  AssessmentRun,
  CreateEngagementRequest,
  CreateRunRequest,
  EngagementDecisionRequest,
  EngagementRecord,
  EngagementTransitionRequest,
  FindingRecord,
  FindingUpdateRequest,
} from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ActionState = { error: string } | null;
const UUID = /^[0-9a-f-]{36}$/;
const fail = (e: unknown): ActionState => {
  if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
  throw e;
};
const lines = (v: FormDataEntryValue | null) =>
  String(v ?? '')
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);

export async function createEngagement(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const parsed = CreateEngagementRequest.safeParse({
    reference: formData.get('reference'),
    authorizingOrganization: formData.get('authorizingOrganization'),
    authorizationReference: formData.get('authorizationReference'),
    objective: formData.get('objective'),
    scope: {
      includeCidrs: lines(formData.get('includeCidrs')),
      includeAddresses: lines(formData.get('includeAddresses')),
      excludeCidrs: lines(formData.get('excludeCidrs')),
      excludeAddresses: lines(formData.get('excludeAddresses')),
      allowPublicAddresses: false,
      allowedTechniques: formData.getAll('technique').map(String),
      windowStart: new Date(String(formData.get('windowStart') ?? '')).toISOString(),
      windowEnd: new Date(String(formData.get('windowEnd') ?? '')).toISOString(),
      maxConcurrency: Number(formData.get('maxConcurrency') ?? 2),
      maxRequestsPerSecond: Number(formData.get('maxRequestsPerSecond') ?? 5),
    },
    stopConditions: lines(formData.get('stopConditions')),
    emergencyContact: formData.get('emergencyContact'),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  let id: string;
  try {
    id = (
      await apiFetch('/api/v1/assessments/engagements', EngagementRecord, {
        method: 'POST',
        body: JSON.stringify(parsed.data),
      })
    ).id;
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/red-team');
  redirect(`/red-team/${id}`);
}

export async function transitionEngagement(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid id' };
  const reason = String(formData.get('reason') ?? '').trim();
  const parsed = EngagementTransitionRequest.safeParse({
    to: formData.get('to'),
    ...(reason ? { reason } : {}),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/assessments/engagements/${id}/transition`, EngagementRecord, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath(`/red-team/${id}`);
  revalidatePath('/red-team');
  return null;
}

export async function decideEngagement(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  const decision = String(formData.get('decision') ?? '');
  if (!UUID.test(id) || !['approve', 'reject'].includes(decision))
    return { error: 'invalid request' };
  const parsed = EngagementDecisionRequest.safeParse({
    justification: formData.get('justification'),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/assessments/engagements/${id}/${decision}`, EngagementRecord, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath(`/red-team/${id}`);
  return null;
}

export async function createRun(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid id' };
  const ports = lines(formData.get('ports')).map(Number);
  const parsed = CreateRunRequest.safeParse({
    technique: formData.get('technique'),
    dryRun: formData.get('dryRun') !== 'false',
    ...(ports.length ? { ports } : {}),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/assessments/engagements/${id}/runs`, AssessmentRun, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath(`/red-team/${id}`);
  return null;
}

export async function runOp(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const runId = String(formData.get('runId') ?? '');
  const engagementId = String(formData.get('id') ?? '');
  const op = String(formData.get('op') ?? '');
  if (!UUID.test(runId) || !['execute', 'cancel'].includes(op)) return { error: 'invalid request' };
  try {
    await apiFetch(`/api/v1/assessments/runs/${runId}/${op}`, AssessmentRun, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  } catch (e) {
    return fail(e);
  }
  if (UUID.test(engagementId)) revalidatePath(`/red-team/${engagementId}`);
  return null;
}

export async function updateFinding(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid id' };
  const parsed = FindingUpdateRequest.safeParse({
    status: formData.get('status'),
    note: formData.get('note'),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/findings/${id}`, FindingRecord, {
      method: 'PATCH',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/vulnerabilities');
  return null;
}
