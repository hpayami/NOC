import { cookies } from 'next/headers';
import { DEFAULT_LOCALE, LOCALES, dirOf, translator, type Locale } from './messages';

export const LOCALE_COOKIE = 'noc_locale';

export async function getLocale(): Promise<Locale> {
  const store = await cookies();
  const v = store.get(LOCALE_COOKIE)?.value;
  return (LOCALES as readonly string[]).includes(v ?? '') ? (v as Locale) : DEFAULT_LOCALE;
}

export async function getI18n() {
  const locale = await getLocale();
  return { locale, dir: dirOf(locale), t: translator(locale) };
}
