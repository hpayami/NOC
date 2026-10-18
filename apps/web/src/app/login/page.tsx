import { redirect } from 'next/navigation';
import { getI18n } from '@/i18n/server';
import { getAccessToken } from '@/lib/session';
import { LocaleSwitch } from '@/components/locale-switch';
import { LoginForm } from './login-form';

export const metadata = { title: 'Login' };

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  if (await getAccessToken()) redirect('/command-center');
  const { t } = await getI18n();
  const { reason } = await searchParams;

  return (
    <main className="flex min-h-full items-center justify-center p-6">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface p-8 shadow-2xl">
        <div className="mb-6 flex items-start justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-widest text-muted">{t('app.phase')}</p>
            <h1 className="mt-1 text-2xl font-semibold">{t('auth.login.title')}</h1>
            <p className="mt-2 text-sm text-muted">{t('auth.login.subtitle')}</p>
          </div>
          <LocaleSwitch label={t('common.locale')} />
        </div>
        <LoginForm
          initialError={reason === 'expired' ? t('auth.error.expired') : null}
          labels={{
            email: t('auth.email'),
            password: t('auth.password'),
            submit: t('auth.submit'),
            submitting: t('auth.submitting'),
            errors: {
              'auth.error.invalid': t('auth.error.invalid'),
              'auth.error.rate': t('auth.error.rate'),
              'auth.error.unavailable': t('auth.error.unavailable'),
            },
          }}
        />
        <p className="mt-6 text-xs text-muted">{t('footer.notice')}</p>
      </div>
    </main>
  );
}
