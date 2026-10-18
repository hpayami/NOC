import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getI18n } from '@/i18n/server';
import { NAV } from '@/lib/nav';
import { getSessionUser } from '@/lib/session';
import { LocaleSwitch } from '@/components/locale-switch';
import { SessionKeeper } from '@/components/session-keeper';
import { NavLink } from '@/components/nav-link';

export default async function ShellLayout({ children }: { children: React.ReactNode }) {
  const user = await getSessionUser();
  if (!user) redirect('/login?reason=expired');
  const { t } = await getI18n();
  const permissions = new Set(user.permissions);
  const visible = NAV.filter((n) => permissions.has(n.permission));

  return (
    <div className="flex min-h-full">
      <SessionKeeper expiresInSeconds={Number(process.env.NEXT_PUBLIC_ACCESS_TTL_SECONDS ?? 900)} />
      <aside className="hidden w-64 shrink-0 flex-col border-e border-border bg-surface md:flex">
        <div className="border-b border-border px-5 py-4">
          <Link href="/command-center" className="block">
            <span className="text-xs uppercase tracking-widest text-muted">{t('app.short')}</span>
            <span className="mt-0.5 block text-sm font-semibold leading-tight">
              {t('app.name')}
            </span>
          </Link>
        </div>
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Primary">
          <ol className="space-y-0.5">
            {visible.map((item, i) => (
              <li key={item.slug}>
                <NavLink
                  href={`/${item.slug}`}
                  index={i + 1}
                  label={t(item.label)}
                  implemented={item.implemented}
                  phase={item.phase}
                />
              </li>
            ))}
          </ol>
        </nav>
        <div className="border-t border-border px-4 py-3 text-xs text-muted">{t('app.phase')}</div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-border bg-surface px-4 py-3 md:px-6">
          <div className="min-w-0 text-sm">
            <span className="font-medium">{user.displayName}</span>
            <span className="mx-2 text-muted">·</span>
            <span className="text-muted">{user.roles.join(', ') || '—'}</span>
          </div>
          <div className="flex items-center gap-2">
            <LocaleSwitch label={t('common.locale')} />
            <form action="/auth/logout" method="post">
              <button
                type="submit"
                className="rounded-md border border-border px-3 py-1 text-xs text-muted hover:text-fg"
              >
                {t('auth.logout')}
              </button>
            </form>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6">{children}</main>
        <footer className="border-t border-border px-6 py-3 text-xs text-muted">
          {t('footer.notice')}
        </footer>
      </div>
    </div>
  );
}
