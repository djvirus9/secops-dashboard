import { test, expect } from '@playwright/test';

const spoofedAuthorization = 'Basic ' + Buffer.from('attacker:unused').toString('base64');
const backend = 'http://127.0.0.1:15101';
const findingId = '00000001-1111-4111-8111-111111111111';

test.beforeEach(async ({ request }) => { await request.post(`${backend}/__test/reset`, { data: {} }); });

test('production proxy accepts canonical public origins without trusting forwarded hosts', async ({ request }) => {
  const publicHeaders = { Authorization: spoofedAuthorization, Host: 'dashboard.secops.invalid', Cookie: 'secops_session=regression-session', 'X-API-Key': 'untrusted-key', 'X-SecOps-User': 'attacker', 'X-Forwarded-Host': 'dashboard.secops.invalid', 'X-Forwarded-Proto': 'https' };
  expect((await request.get('/api/assets', { headers: publicHeaders })).status()).toBe(200);
  const write = await request.post('/api/assets/upsert', { headers: { ...publicHeaders, Origin: 'https://dashboard.secops.invalid' }, data: { key: 'public.invalid', project: 'fixture' } });
  expect(write.status()).toBe(200);
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.at(-1)).toMatchObject({ actor: 'reviewer', hasAuthorization: false, hasApiKey: false, hasSpoofedUser: false, body: { key: 'public.invalid' } });
});

for (const origin of [null, 'null', 'https://attacker.invalid', 'https://dashboard.secops.invalid.attacker.invalid', 'https://dashboard.secops.invalid/path', 'https://dashboard.secops.invalid/', 'https://dashboard.secops.invalid:8443', 'http://0.0.0.0:15100']) {
  test(`production proxy rejects mutation Origin ${origin === null ? "missing" : origin}`, async ({ request }) => {
    const headers: Record<string, string> = { Authorization: spoofedAuthorization, Host: 'attacker.invalid', 'X-Forwarded-Host': 'attacker.invalid', 'X-Forwarded-Proto': 'https' };
    if (origin !== null) headers.Origin = origin;
    const response = await request.post('/api/assets/upsert', { headers, data: { key: 'rejected.invalid' } });
    expect(response.status()).toBe(403);
    const state = await (await request.get(`${backend}/__test/state`)).json();
    expect(state.requests).toHaveLength(0);
  });
}

test('cross-site fetch metadata remains rejected with an allowlisted Origin', async ({ request }) => {
  const response = await request.post('/api/assets/upsert', { headers: { Authorization: spoofedAuthorization, Origin: 'https://dashboard.secops.invalid', 'Sec-Fetch-Site': 'cross-site' }, data: {} });
  expect(response.status()).toBe(403);
});

test('authentication and malformed deployment settings fail closed', async ({ request }) => {
  // Native fetch has no inherited Playwright httpCredentials.
  expect((await fetch('http://127.0.0.1:15100/api/assets')).status).toBe(401);
  for (const port of [15102, 15103]) {
    await expect.poll(async () => {
      try { return (await request.get(`http://127.0.0.1:${port}/_health`)).status(); } catch { return 0; }
    }).toBe(503);
    expect((await request.get(`http://127.0.0.1:${port}/api/assets`, { headers: { Authorization: spoofedAuthorization } })).status()).toBe(503);
  }
});

test('findings pagination reaches records after 100 and filters reset the offset', async ({ page, request }) => {
  await page.goto('/findings');
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('51–100 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('101–121 of 121');
  await expect(page.getByRole('link', { name: 'Finding 121', exact: true })).toBeVisible();
  await page.getByLabel('Search findings').fill('Finding 1');
  await page.getByLabel('Severity', { exact: true }).selectOption('high');
  await page.getByLabel('Project', { exact: true }).fill('payments');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–33 of 33');
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.findLast((entry: { path: string }) => entry.path === '/findings').query).toMatchObject({ offset: '0', limit: '50', q: 'Finding 1', severity: 'high', project: 'payments', sort: 'risk_desc' });
});

test('a failed finding save preserves the draft and allows a successful retry and comment', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failPatch: 1 } });
  await page.goto(`/findings/${findingId}`);
  await page.getByLabel('Status', { exact: true }).selectOption('investigating');
  await page.getByLabel('Assignee', { exact: true }).fill('reviewer');
  await page.getByRole('button', { name: 'Update Finding' }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Temporary save failure');
  await expect(page.getByLabel('Assignee', { exact: true })).toHaveValue('reviewer');
  await expect(page.getByRole('heading', { name: 'Finding 1', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Update Finding' }).click();
  await expect(page.getByRole('status').filter({ hasText: /^Finding updated\.$/ })).toHaveText('Finding updated.');
  await expect(page.getByRole('main').getByRole('alert')).toHaveCount(0);
  await page.getByRole('textbox', { name: 'Comment', exact: true }).fill('Review complete');
  await page.getByRole('button', { name: 'Add Comment' }).click();
  await expect(page.getByText('Review complete', { exact: true })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Comment', exact: true })).toBeEmpty();
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  await expect(page.getByText('fixture-package @ 1.0', { exact: false })).toBeVisible();
});

test('read failures are recoverable and integration failures preserve the scanner catalog', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failFindings: 1, failIntegrations: 1, failSummary: 1 } });
  await page.goto('/findings');
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Findings temporarily unavailable');
  await expect(page.getByText('Loading findings…')).toHaveCount(0);
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 121');
  await page.goto('/integrations');
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Integration service unavailable');
  await expect(page.getByText('Not configured', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Scanners (2)', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Bandit', exact: true })).toBeVisible();
  await expect(page.getByText('Compatibility adapter · Import disabled', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toHaveCount(0);
  await page.goto('/');
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Summary unavailable');
  await expect(page.getByText('API available', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toHaveCount(0);
});

test('asset pagination, cancel and create work through the authenticated browser proxy', async ({ page, request }) => {
  await page.goto('/assets');
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('51–100 of 121');
  await page.getByRole('button', { name: 'Edit Asset 51', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel', exact: true }).first().click();
  await page.getByRole('button', { name: 'Add Asset', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Add New Asset', exact: true })).toBeVisible();
  await expect(page.getByLabel('Key (unique identifier)', { exact: true })).toBeEnabled();
  await expect(page.getByLabel('Key (unique identifier)', { exact: true })).toBeEmpty();
  await page.getByLabel('Key (unique identifier)', { exact: true }).fill('browser-created.invalid');
  await page.getByLabel('Project', { exact: true }).fill('browser-project');
  await page.getByRole('button', { name: 'Create Asset', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 122');
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.assets[0]).toMatchObject({ key: 'browser-created.invalid', project: 'browser-project' });
});

test('imports include project identity and disable unavailable parsers', async ({ page, request }) => {
  await page.goto('/integrations');
  await page.getByRole('button', { name: 'Import Scans', exact: true }).click();
  await expect(page.locator('option[value="legacy"]')).toBeDisabled();
  await page.getByLabel('Project / repository', { exact: true }).fill('payments-api');
  await page.getByLabel('Parser (optional - auto-detect if empty)', { exact: true }).selectOption('bandit');
  await page.getByLabel('Scan Output (JSON, XML, CSV, or JSONL)', { exact: true }).fill('{"results":[]}');
  await page.getByRole('button', { name: 'Import Scan Results', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Imported fixture successfully' })).toContainText('Imported fixture successfully');
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.findLast((entry: { path: string }) => entry.path === '/import/scan')).toMatchObject({ path: '/import/scan', body: { project: 'payments-api', parser: 'bandit' } });
});

test('mobile navigation and forms fit the viewport and retain accessible names', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  for (const path of ['/', '/integrations', '/risks', `/findings/${findingId}`]) {
    await page.goto(path);
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await expect(page.getByLabel('Status', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Assignee', { exact: true })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Comment', exact: true })).toBeVisible();
});

test('dashboard styling preserves borders, focus indicators and the saved theme', async ({ page }) => {
  // The dashboard's explicit theme preference takes precedence over the OS theme.
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('/');
  const toggle = page.getByRole('button', { name: 'Toggle dark mode' });
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  const colors = await page.evaluate(() => {
    const probe = document.createElement('span');
    document.body.append(probe);
    const result: Record<string, string> = {};
    for (const shade of ['50', '200', '700', '900']) {
      probe.style.color = `var(--color-gray-${shade})`;
      result[shade] = getComputedStyle(probe).color;
    }
    probe.remove();
    return result;
  });
  await expect(page.locator('body')).toHaveCSS('background-color', colors['50']);
  await expect(page.locator('header')).toHaveCSS('border-bottom-color', colors['200']);
  const card = page.getByText('API Status', { exact: true }).locator('..');
  await expect(card).toHaveCSS('border-width', '1px');
  await expect(card).toHaveCSS('border-color', colors['200']);
  await expect(card).toHaveCSS('box-shadow', /0px 1px 2px/);
  await expect(toggle).toHaveCSS('cursor', 'pointer');

  const buttonPosition = await toggle.boundingBox();
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to content' });
  await expect(skip).toBeFocused();
  expect(await toggle.boundingBox()).toEqual(buttonPosition);
  await expect(skip).toHaveCSS('outline-width', '2px');
  await expect(skip).toHaveCSS('outline-offset', '2px');

  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('body')).toHaveCSS('background-color', colors['900']);
  await expect(page.locator('header')).toHaveCSS('border-bottom-color', colors['700']);
  await page.reload();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('body')).toHaveCSS('background-color', colors['900']);
});

test('history shows import outcomes and ambiguous delivery retries require explicit confirmation', async ({ page, request }) => {
  await page.goto('/imports');
  await expect(page.getByRole('cell', { name: 'completed', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: '2 imported 1 new · 1 matched', exact: true })).toBeVisible();
  await page.goto('/notifications');
  const retry = page.getByRole('button', { name: 'Retry delivery', exact: true });
  await expect(retry).toBeDisabled();
  await page.getByRole('checkbox', { name: 'I checked Jira and confirmed no issue was created.', exact: true }).check();
  await retry.click();
  await expect(page.getByRole('heading', { name: 'jira · pending', exact: true })).toBeVisible();
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.findLast((entry: { method: string }) => entry.method === 'POST').body).toEqual({ confirmed_no_issue: true });
});

test('login validates credentials, rejects external return paths and logout revokes the session', async ({ page, context }) => {
  await context.clearCookies();
  await page.goto('/findings?project=payments&severity=high');
  await expect(page).toHaveURL(/\/login\?next=/);
  await page.getByLabel('Username', { exact: true }).fill('reviewer');
  await page.getByLabel('Password', { exact: true }).fill('wrong-password');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Invalid username or password');
  await page.getByLabel('Password', { exact: true }).fill('Regression-password-7S9rY2aK5qW8');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL(/\/findings\?project=payments&severity=high/);
  await expect(page.getByLabel('Project', { exact: true })).toHaveValue('payments');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  expect((await context.request.get('/api/auth/me')).status()).toBe(401);
  await page.goto('/login?next=https://attacker.invalid');
  await page.getByLabel('Username', { exact: true }).fill('reviewer');
  await page.getByLabel('Password', { exact: true }).fill('Regression-password-7S9rY2aK5qW8');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page).toHaveURL('http://127.0.0.1:15100/');
});

test('expired sessions return to login with findings filters intact', async ({ page, request }) => {
  await page.goto('/findings?project=payments&q=Finding%201');
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–33 of 33');
  await request.post(`${backend}/__test/expire`);
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.getByLabel('Username', { exact: true }).fill('reviewer');
  await page.getByLabel('Password', { exact: true }).fill('Regression-password-7S9rY2aK5qW8');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByLabel('Search findings')).toHaveValue('Finding 1');
  await expect(page.getByLabel('Project', { exact: true })).toHaveValue('payments');
});

test('saved views persist applied filters, support rename/delete and browser history', async ({ page }) => {
  await page.goto('/findings?project=payments&severity=high&unknown=ignored');
  await expect(page.getByLabel('Severity', { exact: true })).toHaveValue('high');
  await page.getByLabel('View name', { exact: true }).fill('My high findings');
  await page.getByRole('button', { name: 'Save current filters' }).click();
  await expect(page.getByText('View saved.', { exact: true })).toBeVisible();
  await page.getByLabel('Saved view', { exact: true }).selectOption({ label: 'My high findings' });
  await page.getByLabel('View name', { exact: true }).fill('Review queue');
  await page.getByRole('button', { name: 'Rename selected view' }).click();
  await expect(page.getByLabel('Saved view', { exact: true }).locator('option')).toHaveText(['Choose a view', 'Review queue']);
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect(page.getByLabel('Severity', { exact: true })).toHaveValue('');
  await page.goBack();
  await expect(page.getByLabel('Severity', { exact: true })).toHaveValue('high');
  await page.goForward();
  await page.getByLabel('Saved view', { exact: true }).selectOption({ label: 'Review queue' });
  await page.getByRole('button', { name: 'Apply saved view' }).click();
  await expect(page.getByLabel('Project', { exact: true })).toHaveValue('payments');
  await expect(page).not.toHaveURL(/unknown=/);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Delete view' }).click();
  await expect(page.getByText('Saved view deleted.', { exact: true })).toBeVisible();
});

test('bulk updates require explicit closure confirmation, preserve failed drafts and clear page selection', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failBulk: 1 } });
  await page.goto('/findings');
  await page.getByRole('checkbox', { name: 'Select Finding 1', exact: true }).check();
  await page.getByRole('checkbox', { name: 'Select Finding 2', exact: true }).check();
  await page.getByLabel('Bulk status', { exact: true }).selectOption('resolved');
  await page.getByLabel('Assignment action').selectOption('clear');
  const apply = page.getByRole('button', { name: 'Apply to 2 selected' });
  await expect(apply).toBeDisabled();
  await page.getByRole('checkbox', { name: 'Confirm marking 2 selected findings as resolved' }).check();
  await apply.click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Bulk update temporarily unavailable');
  await expect(page.getByLabel('Bulk status', { exact: true })).toHaveValue('resolved');
  await apply.click();
  await expect(page.getByText('Updated 2 selected findings.', { exact: true })).toBeVisible();
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.findLast((entry: { path: string }) => entry.path === '/findings/bulk').body).toMatchObject({ status: 'resolved', assignee: null });
  await page.getByRole('checkbox', { name: 'Select all findings on this page' }).check();
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('heading', { name: /Update \d+ selected findings/ })).toHaveCount(0);
  await expect(page.getByRole('checkbox', { name: 'Select all findings on this page' })).not.toBeChecked();
});

test('CSV export uses current filters and shows server bounds errors', async ({ page, request }) => {
  await page.goto('/findings?q=Finding%20121&project=payments');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export matching CSV' }).click();
  expect((await downloadPromise).suggestedFilename()).toBe('secops-findings.csv');
  let state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.findLast((entry: { path: string }) => entry.path === '/findings/export.csv').query).toMatchObject({ q: 'Finding 121', project: 'payments' });
  await request.post(`${backend}/__test/reset`, { data: { failExport: true } });
  await page.getByRole('button', { name: 'Export matching CSV' }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('refine your filters');
});

test('viewer controls are read-only and analysts never fetch integration configuration', async ({ page, context, request }) => {
  await context.clearCookies();
  const login = async (username: string) => {
    await page.goto('/login');
    await page.getByLabel('Username', { exact: true }).fill(username);
    await page.getByLabel('Password', { exact: true }).fill('Regression-password-7S9rY2aK5qW8');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  };
  await login('viewer');
  await page.goto('/findings');
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 121');
  await expect(page.getByRole('checkbox', { name: /Select/ })).toHaveCount(0);
  await page.goto(`/findings/${findingId}`);
  await expect(page.getByRole('button', { name: 'Update Finding' })).toHaveCount(0);
  await expect(page.getByRole('textbox', { name: 'Comment', exact: true })).toHaveCount(0);
  await page.goto('/assets');
  await expect(page.getByRole('button', { name: 'Add Asset' })).toHaveCount(0);
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Users', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await login('analyst');
  await page.goto('/integrations');
  await expect(page.getByRole('button', { name: 'Import Scan Results', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Notifications', exact: true })).toHaveCount(0);
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.filter((entry: { path: string; actor: string }) => entry.actor === 'analyst' && entry.path === '/integrations')).toHaveLength(0);
});

test('login also requires an exact trusted Origin and invalid sessions stay JSON at the API', async ({ request }) => {
  for (const origin of [undefined, 'null', 'https://attacker.invalid']) {
    const response = await request.post('/api/auth/login', { headers: origin ? { Origin: origin } : {}, data: { username: 'reviewer', password: 'Regression-password-7S9rY2aK5qW8' } });
    expect(response.status()).toBe(403);
  }
  const response = await request.get('/api/findings', { headers: { Cookie: 'secops_session=invalid', Authorization: spoofedAuthorization, 'X-API-Key': 'untrusted-key', 'X-SecOps-User': 'reviewer' } });
  expect(response.status()).toBe(401);
  expect(response.headers()['content-type']).toContain('application/json');
  expect(response.headers().location).toBeUndefined();
});
