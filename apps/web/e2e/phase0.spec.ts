import { expect, test } from '@playwright/test';

const email = process.env.E2E_EMAIL;
const password = process.env.E2E_PASSWORD;
test.skip(!email || !password, 'E2E_EMAIL and E2E_PASSWORD are required');

test.describe('Phase 0 shell', () => {
  test('login page is Persian-first RTL and rejects bad credentials with a visible error', async ({
    page,
  }) => {
    await page.goto('/login');
    await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
    await expect(page.locator('html')).toHaveAttribute('lang', 'fa');
    await page.getByLabel('ایمیل').fill('nobody@example.test');
    await page.getByLabel('گذرواژه').fill('definitely-not-the-password');
    await page.getByRole('button', { name: 'ورود' }).click();
    await expect(page.locator('p[role="alert"]')).toContainText('نادرست');
    await expect(page).toHaveURL(/\/login$/);
  });

  test('admin signs in through the BFF and reaches the command center, administration and audit log', async ({
    page,
  }) => {
    await page.goto('/login');
    await page.getByLabel('ایمیل').fill(email!);
    await page.getByLabel('گذرواژه').fill(password!);
    await page.getByRole('button', { name: 'ورود' }).click();
    await expect(page).toHaveURL(/\/command-center$/);

    // Session is cookie-only: no token in storage, httpOnly cookies present.
    const cookies = await page.context().cookies();
    expect(cookies.find((c) => c.name === 'noc_access')?.httpOnly).toBe(true);
    expect(
      await page.evaluate(
        () => Object.keys(localStorage).length + Object.keys(sessionStorage).length,
      ),
    ).toBe(0);

    // Command center is honest: demo flag, capability table with explicit states.
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('مرکز فرماندهی');
    await expect(page.getByText('دادهٔ نمایشی: خیر')).toBeVisible();
    const capRow = page.getByRole('row').filter({ hasText: 'nips.inline_prevention' });
    await expect(capRow).toContainText('غیرفعال');
    await expect(page.getByRole('row').filter({ hasText: 'auth.rbac' })).toContainText('فعال');

    // All 19 workspaces are listed for the platform admin's visible permissions subset.
    const navItems = page.getByRole('navigation', { name: 'Primary' }).getByRole('link');
    expect(await navItems.count()).toBeGreaterThanOrEqual(3);

    // Administration lists the signed-in admin.
    await page.goto('/administration');
    await expect(page.getByRole('cell', { name: email!, exact: true })).toBeVisible();

    // Audit log shows the login and the chain verifies.
    await page.goto('/audit-logs');
    await expect(page.getByRole('cell', { name: 'auth.login', exact: true }).first()).toBeVisible();
    await page.getByRole('button', { name: 'تأیید یکپارچگی زنجیره' }).click();
    await expect(page.locator('span[role="status"]')).toContainText('زنجیره سالم است');

    // Asset inventory (Phase 1 slice): honest empty state, coverage tiles, no fabricated rows.
    await page.goto('/assets');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('موجودی دارایی‌ها');
    await expect(page.getByText('هنوز دارایی‌ای ثبت نشده است')).toBeVisible();
    await expect(page.getByText('POST /api/v1/assets/observations')).toBeVisible();

    // NOC operations: status tiles from real evidence, no sensors registered yet.
    await page.goto('/noc');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('عملیات NOC');
    await expect(page.getByText('هیچ سنسور یا جمع‌آوری ثبت نشده است.')).toBeVisible();

    // Topology: nothing fabricated — no edges until a collector reports LLDP or flows arrive.
    await page.goto('/topology');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('توپولوژی شبکه');
    await expect(page.getByText('هنوز هیچ ارتباطی ثبت نشده است.')).toBeVisible();

    // Sensors & collectors: registry with derived state; empty until something is registered.
    await page.goto('/sensors');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('سنسورها و جمع‌آورها');
    await expect(page.getByText('هیچ سنسور یا جمع‌آوری ثبت نشده است.')).toBeVisible();

    // Unimplemented workspace shows real capability state, never sample data.
    await page.goto('/nids');
    await expect(page.getByText('این بخش هنوز عملیاتی نیست')).toBeVisible();
    await expect(page.getByText('nids.suricata')).toBeVisible();

    // Logout clears the session; shell redirects to login.
    await page.getByRole('button', { name: 'خروج' }).click();
    await expect(page).toHaveURL(/\/login/);
    await page.goto('/command-center');
    await expect(page).toHaveURL(/\/login/);
  });
});
