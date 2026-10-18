'use server';

import { redirect } from 'next/navigation';
import { CreateUserRequest, User } from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export interface CreateUserState {
  error: string | null;
}

export async function createUserAction(
  _prev: CreateUserState,
  formData: FormData,
): Promise<CreateUserState> {
  const parsed = CreateUserRequest.safeParse({
    email: formData.get('email'),
    displayName: formData.get('displayName'),
    password: formData.get('password'),
    roles: formData.getAll('roles'),
  });
  if (!parsed.success)
    return {
      error: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    };
  try {
    await apiFetch('/api/v1/users', User, { method: 'POST', body: JSON.stringify(parsed.data) });
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
  redirect('/administration?created=1');
}
