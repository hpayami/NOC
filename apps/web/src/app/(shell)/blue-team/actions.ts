'use server';

import { revalidatePath } from 'next/cache';
import {
  CreateDetectionValidationRequest,
  CreateValidationScheduleRequest,
  DetectionValidation,
  ValidationSchedule,
} from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ValidateState = { queued: string } | { error: string } | null;
export type ScheduleState = { saved: true } | { error: string } | null;

export async function requestValidation(
  _prev: ValidateState,
  formData: FormData,
): Promise<ValidateState> {
  const note = String(formData.get('note') ?? '').trim();
  const parsed = CreateDetectionValidationRequest.safeParse({
    ruleId: formData.get('ruleId'),
    sensorId: formData.get('sensorId'),
    sampleRef: String(formData.get('sampleRef') ?? '').trim(),
    note: note || null,
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    const v = await apiFetch('/api/v1/detection-rules/validations', DetectionValidation, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
    revalidatePath('/blue-team');
    return { queued: v.id };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}

export async function requestSchedule(
  _prev: ScheduleState,
  formData: FormData,
): Promise<ScheduleState> {
  const note = String(formData.get('note') ?? '').trim();
  const parsed = CreateValidationScheduleRequest.safeParse({
    ruleId: formData.get('ruleId'),
    sensorId: formData.get('sensorId'),
    sampleRef: String(formData.get('sampleRef') ?? '').trim(),
    intervalDays: Number(formData.get('intervalDays') ?? 7),
    note: note || null,
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch('/api/v1/detection-rules/validation-schedules', ValidationSchedule, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
    revalidatePath('/blue-team');
    return { saved: true };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}

export async function setScheduleEnabled(
  _prev: ScheduleState,
  formData: FormData,
): Promise<ScheduleState> {
  const id = String(formData.get('id') ?? '');
  if (!/^[0-9a-f-]{36}$/.test(id)) return { error: 'invalid id' };
  try {
    await apiFetch(`/api/v1/detection-rules/validation-schedules/${id}`, ValidationSchedule, {
      method: 'PATCH',
      body: JSON.stringify({ enabled: formData.get('enabled') === 'true' }),
    });
    revalidatePath('/blue-team');
    return { saved: true };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
