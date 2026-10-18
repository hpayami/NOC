'use server';

import { revalidatePath } from 'next/cache';
import { ImportIndicatorsRequest, ImportIndicatorsResponse, IndicatorRecord } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ImportState = { result: ImportIndicatorsResponse } | { error: string } | null;
export type RevokeState = { revoked: true } | { error: string } | null;

export async function importIndicators(
  _prev: ImportState,
  formData: FormData,
): Promise<ImportState> {
  const parsed = ImportIndicatorsRequest.safeParse({
    format: formData.get('format'),
    source: formData.get('source'),
    content: formData.get('content'),
    defaultSeverity: formData.get('defaultSeverity') ?? undefined,
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    const result = await apiFetch(
      '/api/v1/threat-intel/indicators/import',
      ImportIndicatorsResponse,
      {
        method: 'POST',
        body: JSON.stringify(parsed.data),
      },
    );
    revalidatePath('/threat-intel');
    return { result };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}

export async function revokeIndicator(
  _prev: RevokeState,
  formData: FormData,
): Promise<RevokeState> {
  const id = String(formData.get('id') ?? '');
  if (!/^[0-9a-f-]{36}$/.test(id)) return { error: 'invalid indicator id' };
  try {
    await apiFetch(`/api/v1/threat-intel/indicators/${id}/revoke`, IndicatorRecord, {
      method: 'POST',
    });
    revalidatePath('/threat-intel');
    return { revoked: true };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
