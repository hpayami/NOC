'use server';

import { revalidatePath } from 'next/cache';
import { CreateDetectionValidationRequest, DetectionValidation } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ValidateState = { queued: string } | { error: string } | null;

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
