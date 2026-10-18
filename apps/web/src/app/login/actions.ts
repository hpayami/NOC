'use server';

import { redirect } from 'next/navigation';
import { LoginRequest, TokenResponse } from '@noc/shared';
import { apiPublic } from '@/lib/api';
import { extractApiRefreshCookie, storeSession } from '@/lib/session';
import type { MessageKey } from '@/i18n/messages';

export interface LoginState {
  error: MessageKey | null;
}

export async function loginAction(_prev: LoginState, formData: FormData): Promise<LoginState> {
  const parsed = LoginRequest.safeParse({
    email: formData.get('email'),
    password: formData.get('password'),
  });
  if (!parsed.success) return { error: 'auth.error.invalid' };

  let res: Response;
  try {
    res = await apiPublic('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
  } catch {
    return { error: 'auth.error.unavailable' };
  }
  if (res.status === 429) return { error: 'auth.error.rate' };
  if (res.status !== 200) return { error: 'auth.error.invalid' };

  const body = TokenResponse.safeParse(await res.json());
  if (!body.success) return { error: 'auth.error.unavailable' };
  await storeSession(body.data, extractApiRefreshCookie(res.headers.get('set-cookie')));
  redirect('/command-center');
}
