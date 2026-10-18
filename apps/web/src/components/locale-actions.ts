'use server';

import { cookies } from 'next/headers';
import { revalidatePath } from 'next/cache';
import { LOCALE_COOKIE, getLocale } from '@/i18n/server';

export async function setLocaleAction() {
  const current = await getLocale();
  const next = current === 'fa' ? 'en' : 'fa';
  (await cookies()).set(LOCALE_COOKIE, next, {
    path: '/',
    sameSite: 'lax',
    maxAge: 60 * 60 * 24 * 365,
  });
  revalidatePath('/', 'layout');
}
