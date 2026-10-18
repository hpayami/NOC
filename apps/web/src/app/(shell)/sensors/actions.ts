'use server';

import { EnrolmentTokenResponse } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type EnrolmentState = { token: string; expiresAt: string } | { error: string } | null;

export async function issueEnrolmentToken(
  _prev: EnrolmentState,
  formData: FormData,
): Promise<EnrolmentState> {
  const sensorId = String(formData.get('sensorId') ?? '');
  if (!/^[0-9a-f-]{36}$/.test(sensorId)) return { error: 'invalid sensor id' };
  try {
    const r = await apiFetch(
      `/api/v1/sensors/${sensorId}/enrolment-token`,
      EnrolmentTokenResponse,
      { method: 'POST' },
    );
    return { token: r.token, expiresAt: r.expiresAt };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
