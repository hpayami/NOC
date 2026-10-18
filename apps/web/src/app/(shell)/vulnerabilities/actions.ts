'use server';

import { revalidatePath } from 'next/cache';
import { ImportVulnerabilitiesRequest, ImportVulnerabilitiesResponse } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ImportState = { result: ImportVulnerabilitiesResponse } | { error: string } | null;

export async function importVulnerabilities(
  _prev: ImportState,
  formData: FormData,
): Promise<ImportState> {
  const parsed = ImportVulnerabilitiesRequest.safeParse({
    format: formData.get('format'),
    content: formData.get('content'),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    const result = await apiFetch('/api/v1/vulnerabilities/import', ImportVulnerabilitiesResponse, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
    revalidatePath('/vulnerabilities');
    return { result };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
