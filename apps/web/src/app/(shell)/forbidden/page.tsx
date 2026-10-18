import Link from 'next/link';
import { getI18n } from '@/i18n/server';

export const dynamic = 'force-dynamic';

/** Shown when the API refused a page's data with 403: the UI never hides what the server decided. */
export default async function ForbiddenPage({
  searchParams,
}: {
  searchParams: Promise<{ from?: string }>;
}) {
  const { t } = await getI18n();
  const { from } = await searchParams;
  return (
    <div className="max-w-xl space-y-4">
      <h1 className="text-2xl font-semibold">{t('forbidden.title')}</h1>
      <p className="text-sm text-muted">{t('forbidden.body')}</p>
      {from ? <p className="ltr text-xs text-muted">{from}</p> : null}
      <Link
        href="/command-center"
        className="inline-block rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:text-fg"
      >
        ← {t('nav.command_center')}
      </Link>
    </div>
  );
}
