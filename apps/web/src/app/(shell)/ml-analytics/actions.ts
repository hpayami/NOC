'use server';

import { revalidatePath } from 'next/cache';
import { MlBatchScoreResponse, MlScoreRecord, MlScoreRequest } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type ActionState = { error: string } | { info: string } | null;
const fail = (e: unknown): ActionState => {
  if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
  throw e;
};

export async function scoreAsset(_prev: ActionState, formData: FormData): Promise<ActionState> {
  const parsed = MlScoreRequest.safeParse({
    subjectType: 'asset',
    subjectId: formData.get('subjectId'),
  });
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    await apiFetch('/api/v1/ml/score', MlScoreRecord, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/ml-analytics');
  return null;
}

export async function scoreBatch(_prev: ActionState, _formData: FormData): Promise<ActionState> {
  let out: MlBatchScoreResponse;
  try {
    out = await apiFetch('/api/v1/ml/score/batch', MlBatchScoreResponse, {
      method: 'POST',
      body: JSON.stringify({ limit: 50 }),
    });
  } catch (e) {
    return fail(e);
  }
  revalidatePath('/ml-analytics');
  return { info: `scored ${out.scored}, skipped ${out.skipped.length}` };
}
