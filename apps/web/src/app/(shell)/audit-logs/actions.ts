'use server';

import { AuditVerifyResponse } from '@noc/shared';
import { apiFetch } from '@/lib/api';

export type VerifyState = AuditVerifyResponse | null;

export async function verifyChainAction(): Promise<VerifyState> {
  return apiFetch('/api/v1/audit/verify', AuditVerifyResponse, { method: 'POST' });
}
