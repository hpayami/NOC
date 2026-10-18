'use server';

import { revalidatePath } from 'next/cache';
import { Alert, AlertTriageRequest } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type TriageState = { error: string } | null;

export async function triageAlert(_prev: TriageState, formData: FormData): Promise<TriageState> {
  const alertId = String(formData.get('alertId') ?? '');
  if (!/^[0-9a-f-]{36}$/.test(alertId)) return { error: 'invalid alert id' };
  const note = String(formData.get('note') ?? '').trim();
  const parsed = AlertTriageRequest.safeParse({
    action: formData.get('action'),
    ...(note ? { note } : {}),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch(`/api/v1/alerts/${alertId}`, Alert, {
      method: 'PATCH',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
  revalidatePath('/soc-alerts');
  return null;
}
