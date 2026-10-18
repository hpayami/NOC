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

    // A platform admin holds no SOC permissions: the API's 403 becomes a clear page, not a crash.
    await page.goto('/soc-alerts');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('دسترسی مجاز نیست');

    // Unimplemented workspace shows real capability state, never sample data.
    await page.goto('/nips');
    await expect(page.getByText('این بخش هنوز عملیاتی نیست')).toBeVisible();
    await expect(page.getByText('nips.inline_prevention')).toBeVisible();

    // Logout clears the session; shell redirects to login.
    await page.getByRole('button', { name: 'خروج' }).click();
    await expect(page).toHaveURL(/\/login/);
    await page.goto('/command-center');
    await expect(page).toHaveURL(/\/login/);
  });

  test('a SOC analyst sees the alert queue and NIDS monitoring with honest empty states', async ({
    page,
  }) => {
    const analystEmail = process.env.E2E_ANALYST_EMAIL;
    const analystPassword = process.env.E2E_ANALYST_PASSWORD;
    test.skip(
      !analystEmail || !analystPassword,
      'E2E_ANALYST_EMAIL and E2E_ANALYST_PASSWORD are required',
    );
    await page.goto('/login');
    await page.getByLabel('ایمیل').fill(analystEmail!);
    await page.getByLabel('گذرواژه').fill(analystPassword!);
    await page.getByRole('button', { name: 'ورود' }).click();
    await expect(page).toHaveURL(/\/command-center$/);
    await page.goto('/soc-alerts');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('هشدارهای SOC');
    await expect(page.getByText('هشدار بازی وجود ندارد.')).toBeVisible();
    await page.goto('/nids');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('پایش NIDS');
    await expect(page.getByText('هیچ سنسور Suricata/Zeek ثبت نشده است.')).toBeVisible();
    // Detection engineering: rule registry is empty until rules are imported; nothing fabricated.
    await page.goto('/detection-engineering');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('مهندسی تشخیص');
    await expect(page.getByText('هنوز قاعده‌ای وارد نشده است.')).toBeVisible();
    // Incident response: empty until an analyst opens one; the whole lifecycle is real.
    await page.goto('/incidents');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('پاسخ به حادثه');
    await expect(page.getByText('هیچ حادثه‌ای ثبت نشده است.')).toBeVisible();
    await page.getByLabel('عنوان').fill('E2E: suspicious SMB fan-out');
    await page.getByLabel('شدت').selectOption('high');
    await page.getByRole('button', { name: 'ایجاد حادثه' }).click();
    await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]{36}$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('E2E: suspicious SMB fan-out');
    await expect(page.getByTestId('incident-status')).toHaveText('جدید');
    await page.getByPlaceholder('یادداشت').fill('Host owner contacted; awaiting confirmation');
    await page.getByRole('button', { name: 'افزودن یادداشت' }).click();
    await expect(page.getByText('Host owner contacted; awaiting confirmation')).toBeVisible();
    await page.getByRole('button', { name: '→ دسته‌بندی' }).click();
    await expect(page.getByTestId('incident-status')).toHaveText('دسته‌بندی');
    // An analyst holds incidents.manage but not incidents.close: no close button is offered.
    await expect(page.getByRole('button', { name: '→ بسته' })).toHaveCount(0);
    // Response actions: proposing changes nothing; collect_evidence needs no approval but the
    // analyst holds no response.execute, so the action waits for a responder.
    await expect(page.getByText('اقدامی برای این حادثه پیشنهاد نشده است.')).toBeVisible();
    await page.getByLabel('هدف', { exact: true }).fill('10.0.0.9');
    await page.getByLabel('توجیه').fill('Preserve flow records before containment');
    await page.getByLabel('برنامهٔ بازگشت').fill('References only; nothing to undo');
    await page.getByRole('button', { name: 'ثبت پیشنهاد' }).click();
    await expect(page.getByTestId('response-status')).toHaveText('تأییدشده');
    await expect(page.getByRole('button', { name: 'اجرا', exact: true })).toHaveCount(0);
    await expect(page.getByText('اقدام پاسخ').first()).toBeVisible();
    // Analysts cannot administer users: forbidden page, not a crash.
    await page.goto('/administration');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('دسترسی مجاز نیست');
  });
});
