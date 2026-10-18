'use server';

import { revalidatePath } from 'next/cache';
import {
  IpsDecisionRequest,
  IpsDisableRequest,
  IpsEnableRequest,
  IpsPolicy,
  ProposeIpsPolicyRequest,
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

export async function proposeIpsPolicy(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const parsed = ProposeIpsPolicyRequest.safeParse({
    name: formData.get('name'),
    sensorId: formData.get('sensorId'),
    mode: formData.get('mode'),
    action: formData.get('action') ?? undefined,
    protectedCidrs: lines(formData.get('protectedCidrs')),
    excludedCidrs: lines(formData.get('excludedCidrs')),
    ruleIds: lines(formData.get('ruleIds')),
    justification: formData.get('justification'),
    rollbackPlan: formData.get('rollbackPlan'),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch('/api/v1/ips/policies', IpsPolicy, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/nips');
  return null;
}

export async function decideIpsPolicy(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  const decision = String(formData.get('decision') ?? '');
  if (!UUID.test(id) || !['approve', 'reject'].includes(decision))
    return { error: 'invalid request' };
  const parsed = IpsDecisionRequest.safeParse({ justification: formData.get('justification') });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/ips/policies/${id}/${decision}`, IpsPolicy, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/nips');
  return null;
}

export async function enableIpsPolicy(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid request' };
  const parsed = IpsEnableRequest.safeParse({
    enabledForHours: Number(formData.get('enabledForHours') ?? 24),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/ips/policies/${id}/enable`, IpsPolicy, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/nips');
  return null;
}

export async function disableIpsPolicy(
  _prev: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid request' };
  const parsed = IpsDisableRequest.safeParse({ reason: formData.get('reason') });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/ips/policies/${id}/disable`, IpsPolicy, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/nips');
  return null;
}
