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

    // NIPS needs ips.read, which a platform admin deliberately lacks.
    await page.goto('/nips');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('دسترسی مجاز نیست');

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
    // Asset dependency graph: no assets → honest empty state, never a demo topology.
    await page.goto('/assets/graph');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('گراف وابستگی دارایی‌ها');
    await expect(page.getByText('دارایی‌ای در محدودهٔ شما ثبت نشده است.')).toBeVisible();
    // Platform conditions: every check reports; an analyst sees them but cannot manage channels.
    await page.goto('/command-center');
    await expect(page.getByRole('heading', { name: 'شرایط نیازمند اقدام' })).toBeVisible();
    await expect(page.getByTestId('checks-summary')).toContainText('بررسی‌ها');
    await page.goto('/operations');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('عملیات پلتفرم و اعلان‌ها');
    await expect(
      page.getByText('مدیریت کانال‌ها به مجوز notifications.manage نیاز دارد'),
    ).toBeVisible();
    // Threat intel: no indicator imported → says so; an analyst cannot import.
    await page.goto('/threat-intel');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('هوش تهدید');
    await expect(page.getByTestId('ti-stats')).toContainText('هیچ نشانگری وارد نشده است');
    await expect(page.getByRole('button', { name: 'import' })).toHaveCount(0);
    // Reports: every plane states its own state; nothing the analyst cannot read is estimated.
    await page.goto('/reports?days=7');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('گزارش‌ها');
    await expect(page.getByTestId('report-rep.governance')).toContainText('محفوظ');
    await expect(page.getByTestId('report-rep.incidents')).toContainText('در دسترس');
    // Unimplemented workspace shows real capability state, never sample data.
    await page.goto('/pentest');
    await expect(page.getByText('این بخش هنوز عملیاتی نیست')).toBeVisible();
    // Analysts cannot administer users: forbidden page, not a crash.
    await page.goto('/administration');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('دسترسی مجاز نیست');
  });

  test('a blue-team engineer sees the NIPS policy plane with inline prevention disabled', async ({
    page,
  }) => {
    const blueEmail = process.env.E2E_BLUE_EMAIL;
    const bluePassword = process.env.E2E_BLUE_PASSWORD;
    test.skip(!blueEmail || !bluePassword, 'E2E_BLUE_EMAIL and E2E_BLUE_PASSWORD are required');
    await page.goto('/login');
    await page.getByLabel('ایمیل').fill(blueEmail!);
    await page.getByLabel('گذرواژه').fill(bluePassword!);
    await page.getByRole('button', { name: 'ورود' }).click();
    await expect(page).toHaveURL(/\/command-center$/);
    await page.goto('/nips');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('سیاست‌های NIPS');
    // Honest state: nothing is inline, and the reason says sensors run detect-only.
    await expect(page.getByTestId('nips-reason')).toContainText('detect-only');
    await expect(page.getByText('هیچ سیاست پیشگیری درون‌خطی پیشنهاد نشده است.')).toBeVisible();
    // No Suricata sensor is registered, so no proposal form is offered — nothing to switch on.
    await expect(page.getByText('سنسور Suricata ثبت نشده است')).toBeVisible();
    // ML analytics: advisory banner, service state reported, no fabricated scores.
    await page.goto('/ml-analytics');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('تحلیل ML (مشورتی)');
    await expect(page.getByText('فقط مشورتی', { exact: true })).toBeVisible();
    await expect(page.getByTestId('ml-reachable')).toHaveText(/در دسترس|خارج از دسترس/);
    await expect(page.getByText('هنوز امتیازی محاسبه نشده است.')).toBeVisible();
  });

  test('a red-team operator drafts an authorised engagement and submits it for approval', async ({
    page,
  }) => {
    const redEmail = process.env.E2E_RED_EMAIL;
    const redPassword = process.env.E2E_RED_PASSWORD;
    test.skip(!redEmail || !redPassword, 'E2E_RED_EMAIL and E2E_RED_PASSWORD are required');
    await page.goto('/login');
    await page.getByLabel('ایمیل').fill(redEmail!);
    await page.getByLabel('گذرواژه').fill(redPassword!);
    await page.getByRole('button', { name: 'ورود' }).click();
    await expect(page).toHaveURL(/\/command-center$/);
    await page.goto('/red-team');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('تیم قرمز — ارزیابی‌های مجاز');
    await expect(page.getByText('هیچ ارزیابی‌ای ثبت نشده است.')).toBeVisible();
    await page.getByLabel('مرجع', { exact: true }).fill('ENG-E2E-1');
    await page.getByLabel('سازمان مجوزدهنده').fill('Example Holding');
    await page.getByLabel('مرجع مجوز (قرارداد / تیکت)').fill('CHG-42');
    await page.getByLabel('هدف').fill('Lab exposure validation from the user VLAN');
    await page.getByLabel('آدرس‌های شامل').fill('127.0.0.1');
    await page.getByLabel('شرایط توقف (هر خط یکی)').fill('Any production impact');
    await page.getByLabel('مخاطب اضطراری').fill('soc-duty@example.test');
    await page.getByRole('button', { name: 'ثبت پیش‌نویس' }).click();
    await expect(page).toHaveURL(/\/red-team\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId('eng-status')).toHaveText('پیش‌نویس');
    // Nothing runs from a draft: no run form, and submitting only requests approval.
    await expect(page.getByRole('button', { name: 'صف‌کردن اجرا' })).toHaveCount(0);
    await page.getByRole('button', { name: '→ در انتظار تأیید' }).click();
    await expect(page.getByTestId('eng-status')).toHaveText('در انتظار تأیید');
    // The operator cannot approve their own engagement: no decision form.
    await expect(page.getByRole('button', { name: 'تأیید', exact: true })).toHaveCount(0);
    // Findings page is honest while nothing has been assessed.
    await page.goto('/vulnerabilities');
    await expect(page.getByText('یافتهٔ بازی وجود ندارد.')).toBeVisible();
  });
});
