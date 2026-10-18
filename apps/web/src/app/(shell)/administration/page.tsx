import { z } from 'zod';
import { Role, UserListResponse } from '@noc/shared';
import { getI18n } from '@/i18n/server';
import { ApiError, apiFetch } from '@/lib/api';
import { getSessionUser } from '@/lib/session';
import { CreateUserForm } from './create-user-form';

export const dynamic = 'force-dynamic';

export default async function AdministrationPage({
  searchParams,
}: {
  searchParams: Promise<{ created?: string }>;
}) {
  const { t, locale } = await getI18n();
  const me = await getSessionUser();
  const perms = new Set(me?.permissions ?? []);
  const { created } = await searchParams;
  const when = new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
    dateStyle: 'short',
    timeStyle: 'short',
  });

  let users: z.infer<typeof UserListResponse> | null = null;
  let roles: z.infer<typeof Role>[] = [];
  let forbidden = false;
  try {
    users = await apiFetch('/api/v1/users?limit=100', UserListResponse);
    if (perms.has('roles.read')) roles = await apiFetch('/api/v1/roles', z.array(Role));
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) forbidden = true;
    else throw e;
  }

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-semibold">{t('admin.title')}</h1>
      {forbidden || !users ? (
        <p className="rounded-md border border-border bg-surface p-4 text-sm text-muted">
          {t('admin.forbidden')}
        </p>
      ) : (
        <>
          <section aria-labelledby="users">
            <h2 id="users" className="mb-3 text-lg font-medium">
              {t('admin.users')}
            </h2>
            {created ? <p className="mb-3 text-sm text-ok">{t('admin.created')}</p> : null}
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-surface text-xs text-muted">
                  <tr>
                    <th className="px-3 py-2 text-start">{t('common.email')}</th>
                    <th className="px-3 py-2 text-start">{t('admin.display_name')}</th>
                    <th className="px-3 py-2 text-start">{t('common.role')}</th>
                    <th className="px-3 py-2 text-start">{t('admin.status')}</th>
                    <th className="px-3 py-2 text-start">{t('admin.last_login')}</th>
                  </tr>
                </thead>
                <tbody>
                  {users.items.map((u) => (
                    <tr key={u.id} className="border-t border-border">
                      <td className="ltr px-3 py-2">{u.email}</td>
                      <td className="px-3 py-2">{u.displayName}</td>
                      <td className="ltr px-3 py-2 text-xs">{u.roles.join(', ') || '—'}</td>
                      <td className="ltr px-3 py-2 text-xs">{u.status}</td>
                      <td className="px-3 py-2 text-xs text-muted">
                        {u.lastLoginAt ? when.format(new Date(u.lastLoginAt)) : t('admin.never')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {perms.has('users.manage') && perms.has('users.assign_roles') ? (
            <section aria-labelledby="create">
              <h2 id="create" className="mb-3 text-lg font-medium">
                {t('admin.create_user')}
              </h2>
              <CreateUserForm
                roles={roles.map((r) => ({
                  key: r.key,
                  name: locale === 'fa' ? r.nameFa : r.name,
                }))}
                labels={{
                  email: t('common.email'),
                  displayName: t('admin.display_name'),
                  password: t('auth.password'),
                  role: t('common.role'),
                  submit: t('admin.create_user'),
                }}
              />
            </section>
          ) : null}

          {roles.length > 0 ? (
            <section aria-labelledby="roles">
              <h2 id="roles" className="mb-3 text-lg font-medium">
                {t('admin.roles')}
              </h2>
              <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {roles.map((r) => (
                  <li key={r.key} className="rounded-lg border border-border bg-surface p-4">
                    <p className="font-medium">{locale === 'fa' ? r.nameFa : r.name}</p>
                    <p className="ltr text-xs text-muted">{r.key}</p>
                    <p className="mt-2 text-xs text-muted">{r.description}</p>
                    <details className="mt-2 text-xs">
                      <summary className="cursor-pointer text-muted">
                        {r.permissions.length} {t('admin.permissions_count')}
                      </summary>
                      <ul className="ltr mt-1 columns-2 text-[11px] text-muted">
                        {r.permissions.map((p) => (
                          <li key={p}>{p}</li>
                        ))}
                      </ul>
                    </details>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </>
      )}
    </div>
  );
}
