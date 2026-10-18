'use server';

import { revalidatePath } from 'next/cache';
import { ImportRulesRequest, ImportRulesResponse } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ImportState = { result: ImportRulesResponse } | { error: string } | null;

export async function importRules(_prev: ImportState, formData: FormData): Promise<ImportState> {
  const parsed = ImportRulesRequest.safeParse({
    source: formData.get('source'),
    ruleSet: formData.get('ruleSet'),
    license: formData.get('license'),
    content: formData.get('content'),
  });
  if (!parsed.success)
    return {
      error: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    };
  try {
    const result = await apiFetch('/api/v1/detection-rules/import', ImportRulesResponse, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
    revalidatePath('/detection-engineering');
    return { result };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
