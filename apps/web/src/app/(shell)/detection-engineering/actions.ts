'use server';

import { revalidatePath } from 'next/cache';
import { DetectionRuleDetail, ImportRulesRequest, ImportRulesResponse } from '@noc/shared';
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

export type RuleActionState = { error: string } | { ok: true } | null;
const UUID = /^[0-9a-f-]{36}$/;

export async function deployRule(
  _prev: RuleActionState,
  formData: FormData,
): Promise<RuleActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid id' };
  try {
    await apiFetch(`/api/v1/detection-rules/${id}/deploy`, DetectionRuleDetail, { method: 'POST' });
    revalidatePath('/detection-engineering');
    return { ok: true };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}

export async function setRuleTargets(
  _prev: RuleActionState,
  formData: FormData,
): Promise<RuleActionState> {
  const id = String(formData.get('id') ?? '');
  if (!UUID.test(id)) return { error: 'invalid id' };
  const sites = String(formData.get('sites') ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  try {
    await apiFetch(`/api/v1/detection-rules/${id}/targets`, DetectionRuleDetail, {
      method: 'PUT',
      body: JSON.stringify({ sites }),
    });
    revalidatePath('/detection-engineering');
    return { ok: true };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
