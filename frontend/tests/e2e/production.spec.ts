import { test, expect } from '@playwright/test';

const basic = 'Basic ' + Buffer.from('reviewer:Regression-password-7S9rY2aK5qW8').toString('base64');
const backend = 'http://127.0.0.1:15101';
const findingId = '00000001-1111-4111-8111-111111111111';

test.beforeEach(async ({ request }) => { await request.post(`${backend}/__test/reset`, { data: {} }); });

test('production proxy accepts canonical public origins without trusting forwarded hosts', async ({ request }) => {
  const publicHeaders = { Authorization: basic, Host: 'dashboard.secops.invalid', 'X-Forwarded-Host': 'dashboard.secops.invalid', 'X-Forwarded-Proto': 'https' };
  expect((await request.get('/api/assets', { headers: publicHeaders })).status()).toBe(200);
  const write = await request.post('/api/assets/upsert', { headers: { ...publicHeaders, Origin: 'https://dashboard.secops.invalid' }, data: { key: 'public.invalid', project: 'fixture' } });
  expect(write.status()).toBe(200);
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.at(-1)).toMatchObject({ actor: 'reviewer', hasAuthorization: false, body: { key: 'public.invalid' } });
});

for (const origin of [null, 'null', 'https://attacker.invalid', 'https://dashboard.secops.invalid.attacker.invalid', 'https://dashboard.secops.invalid/path', 'https://dashboard.secops.invalid/', 'https://dashboard.secops.invalid:8443', 'http://0.0.0.0:15100']) {
  test(`production proxy rejects mutation Origin ${origin === null ? "missing" : origin}`, async ({ request }) => {
    const headers: Record<string, string> = { Authorization: basic, Host: 'attacker.invalid', 'X-Forwarded-Host': 'attacker.invalid', 'X-Forwarded-Proto': 'https' };
    if (origin !== null) headers.Origin = origin;
    const response = await request.post('/api/assets/upsert', { headers, data: { key: 'rejected.invalid' } });
    expect(response.status()).toBe(403);
    const state = await (await request.get(`${backend}/__test/state`)).json();
    expect(state.requests).toHaveLength(0);
  });
}

test('cross-site fetch metadata remains rejected with an allowlisted Origin', async ({ request }) => {
  const response = await request.post('/api/assets/upsert', { headers: { Authorization: basic, Origin: 'https://dashboard.secops.invalid', 'Sec-Fetch-Site': 'cross-site' }, data: {} });
  expect(response.status()).toBe(403);
});

test('authentication and malformed deployment settings fail closed', async ({ request }) => {
  // Native fetch has no inherited Playwright httpCredentials.
  expect((await fetch('http://127.0.0.1:15100/api/assets')).status).toBe(401);
  for (const port of [15102, 15103]) {
    await expect.poll(async () => {
      try { return (await request.get(`http://127.0.0.1:${port}/_health`)).status(); } catch { return 0; }
    }).toBe(503);
    expect((await request.get(`http://127.0.0.1:${port}/api/assets`, { headers: { Authorization: basic } })).status()).toBe(503);
  }
});

test('findings pagination reaches records after 100 and filters reset the offset', async ({ page, request }) => {
  await page.goto('/findings');
  await expect(page.getByRole('status')).toHaveText('1–50 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('51–100 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('101–121 of 121');
  await expect(page.getByRole('link', { name: 'Finding 121', exact: true })).toBeVisible();
  await page.getByLabel('Search findings').fill('Finding 1');
  await page.getByLabel('Severity', { exact: true }).selectOption('high');
  await page.getByLabel('Project', { exact: true }).fill('payments');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('status')).toHaveText('1–33 of 33');
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.at(-1).query).toMatchObject({ offset: '0', limit: '50', q: 'Finding 1', severity: 'high', project: 'payments', sort: 'risk_desc' });
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
  await expect(page.getByRole('status')).toHaveText('Finding updated.');
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
  await expect(page.getByRole('status')).toHaveText('1–50 of 121');
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
  await expect(page.getByRole('status')).toHaveText('1–50 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('51–100 of 121');
  await page.getByRole('button', { name: 'Edit Asset 51', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel', exact: true }).first().click();
  await page.getByRole('button', { name: 'Add Asset', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Add New Asset', exact: true })).toBeVisible();
  await expect(page.getByLabel('Key (unique identifier)', { exact: true })).toBeEnabled();
  await expect(page.getByLabel('Key (unique identifier)', { exact: true })).toBeEmpty();
  await page.getByLabel('Key (unique identifier)', { exact: true }).fill('browser-created.invalid');
  await page.getByLabel('Project', { exact: true }).fill('browser-project');
  await page.getByRole('button', { name: 'Create Asset', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('1–50 of 122');
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
  await expect(page.getByRole('status')).toContainText('Imported fixture successfully');
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.at(-1)).toMatchObject({ path: '/import/scan', body: { project: 'payments-api', parser: 'bandit' } });
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

  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to content' });
  await expect(skip).toBeFocused();
  await expect(skip).toHaveCSS('outline-width', '2px');
  await expect(skip).toHaveCSS('outline-offset', '2px');

  await toggle.click();
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
