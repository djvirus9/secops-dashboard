import { test, expect } from '@playwright/test';
import { verifyAutomation } from './automation-flow';

const fixtures = Array.from({ length: 121 }, (_, index) => ({
  title: `Browser finding ${String(index + 1).padStart(3, '0')}`,
  source_id: `browser-rule-${index + 1}`, severity: index === 0 ? 'high' : 'low',
  asset: 'browser.example.invalid', file_path: 'src/review.py', line_number: index + 1,
  description: 'Evidence from an isolated browser regression', recommendation: 'Apply the fixture fix',
}));

test('migrated backend supports import, triage, rediscovery, asset risk updates and history', async ({ page, browser }) => {
  const request = page.request;
  await page.goto('/login');
  await page.getByLabel('Username', { exact: true }).fill('reviewer');
  await page.getByLabel('Password', { exact: true }).fill('Integration-password-9b7f2d1e6c4a');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  const importScan = async (content: unknown, expectedNew: number) => {
    await page.goto('/integrations');
    await page.getByRole('button', { name: 'Import Scans', exact: true }).click();
    await page.getByLabel('Project / repository', { exact: true }).fill('browser-project');
    await page.getByLabel('Parser (optional - auto-detect if empty)', { exact: true }).selectOption('generic-json');
    await page.getByLabel('Scan Output (JSON, XML, CSV, or JSONL)', { exact: true }).fill(JSON.stringify(content));
    const response = page.waitForResponse((value) => value.url().endsWith('/api/import/scan') && value.request().method() === 'POST');
    await page.getByRole('button', { name: 'Import Scan Results', exact: true }).click();
    const result = await response;
    expect(result.status()).toBe(200);
    expect(await result.json()).toMatchObject({ ok: true, new_findings: expectedNew });
  };
  await importScan(fixtures, 121);
  await page.goto('/findings');
  await page.getByLabel('Project', { exact: true }).fill('browser-project');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('51–100 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('101–121 of 121');
  await page.getByLabel('Search findings').fill('Browser finding 001');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–1 of 1');
  await page.getByRole('link', { name: 'Browser finding 001', exact: true }).click();
  const detailUrl = page.url();
  await expect(page.getByText('Evidence from an isolated browser regression', { exact: true })).toBeVisible();
  await page.getByRole('textbox', { name: 'Comment', exact: true }).fill('Confirmed by the browser regression');
  await page.getByRole('button', { name: 'Add Comment', exact: true }).click();
  await expect(page.getByText('Confirmed by the browser regression', { exact: true })).toBeVisible();
  await page.getByLabel('Status', { exact: true }).selectOption('resolved');
  await page.getByRole('button', { name: 'Update Finding', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: /^Finding updated\.$/ })).toHaveText('Finding updated.');
  await importScan([fixtures[0]], 0);
  await page.goto(detailUrl);
  await expect(page.getByLabel('Status', { exact: true })).toHaveValue('open');
  await expect(page.getByText('Finding resurfaced in a later scan and was reopened', { exact: true })).toBeVisible();
  await page.goto('/assets');
  await page.getByRole('button', { name: 'Edit browser.example.invalid', exact: true }).click();
  await page.getByLabel('Exposure', { exact: true }).selectOption('internet');
  await page.getByLabel('Criticality', { exact: true }).selectOption('high');
  const assetUpdate = page.waitForResponse((response) => response.url().endsWith('/api/assets/upsert') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Update Asset', exact: true }).click();
  expect((await assetUpdate).status()).toBe(200);
  const detail = await (await request.get(detailUrl.replace('/findings/', '/api/findings/'))).json();
  expect(detail).toMatchObject({ project: 'browser-project', risk_score: 195, status: 'open', occurrences: 2 });
  expect(detail.comments.some((comment: { author: string; content: string }) => comment.author === 'reviewer' && comment.content === 'Confirmed by the browser regression')).toBe(true);
  await page.goto('/imports');
  await expect(page.getByRole('cell', { name: 'completed', exact: true })).toHaveCount(2);
  await page.goto('/notifications');
  await expect(page.getByText('No notification deliveries recorded.', { exact: true })).toBeVisible();
  await page.goto('/integrations');
  await expect(page.getByText('Not configured', { exact: true })).toHaveCount(2);

  // Team workflows use the browser's session; the API key is never given to it.
  const origin = 'http://127.0.0.1:15110';
  const hiddenImport = await request.post('/api/import/scan', { headers: { Origin: origin }, data: { parser: 'generic-json', project: 'restricted-project', content: JSON.stringify([{ ...fixtures[0], title: 'Restricted evidence' }]) } });
  expect(hiddenImport.status()).toBe(200);
  const hiddenId = (await (await request.get('/api/findings?project=restricted-project')).json()).results[0].id;
  const visibleId = detailUrl.split('/').at(-1)!;
  const createAccount = async (username: string, role: string) => {
    await page.goto('/users');
    await page.getByLabel('Username', { exact: true }).fill(username);
    await page.getByLabel('Initial password', { exact: true }).fill('Team-browser-password-12345');
    await page.getByLabel('Role', { exact: true }).selectOption(role);
    await page.getByLabel('Allowed projects (one per line)', { exact: true }).fill('browser-project');
    await page.getByRole('button', { name: 'Create account', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: /^Account saved\.$/ })).toHaveText('Account saved.');
    const accountRow = page.getByRole('row').filter({ has: page.getByRole('cell', { name: username, exact: true }) });
    await expect(accountRow.getByRole('cell', { name: role, exact: true })).toBeVisible();
  };
  await createAccount('scoped-viewer', 'viewer');
  await createAccount('scoped-analyst', 'analyst');
  await page.goto('/findings?project=browser-project&severity=high');
  await page.getByLabel('View name', { exact: true }).fill('Admin private view');
  await page.getByRole('button', { name: 'Save current filters' }).click();
  await expect(page.getByText('View saved.', { exact: true })).toBeVisible();
  const adminView = (await (await request.get('/api/saved-views')).json()).results[0];
  expect(adminView.filters.project).toBe('browser-project');

  const viewerContext = await browser.newContext({ baseURL: origin });
  const analystContext = await browser.newContext({ baseURL: origin });
  try {
    const viewer = await viewerContext.newPage();
    const analyst = await analystContext.newPage();
    for (const [client, username] of [[viewer, 'scoped-viewer'], [analyst, 'scoped-analyst']] as const) {
      await client.goto('/login');
      await client.getByLabel('Username', { exact: true }).fill(username);
      await client.getByLabel('Password', { exact: true }).fill('Team-browser-password-12345');
      await client.getByRole('button', { name: 'Sign in', exact: true }).click();
      await expect(client.getByRole('button', { name: 'Sign out' })).toBeVisible();
      await client.goto('/findings');
      await expect(client.getByRole('navigation', { name: 'Pagination' }).getByRole('status')).toHaveText('1–50 of 121');
      await expect(client.getByLabel('Saved view', { exact: true }).locator('option')).toHaveText(['Choose a view']);
      await expect(client.getByRole('navigation').getByRole('link', { name: 'Users', exact: true })).toHaveCount(0);
      for (const [path, label] of [['/scanner-tokens', 'Scanner tokens'], ['/github-sync', 'GitHub sync']]) {
        await expect(client.getByRole('navigation').getByRole('link', { name: label, exact: true })).toHaveCount(0);
        expect((await client.request.get(`/api${path}`)).status()).toBe(403);
      }
      expect((await client.request.get(`/api/findings/${hiddenId}`)).status()).toBe(404);
      expect((await client.request.patch(`/api/saved-views/${adminView.id}`, { headers: { Origin: origin }, data: { name: 'Attempted overwrite' } })).status()).toBe(404);
    }
    await expect(viewer.getByRole('checkbox', { name: /Select/ })).toHaveCount(0);
    const forged = await viewer.request.post('/api/findings/bulk', { headers: { Origin: origin, 'X-API-Key': 'integration-admin-0f2e4a6c8d1b3e5f7a9c', 'X-SecOps-User': 'reviewer', Authorization: 'Basic ignored' }, data: { ids: [visibleId], status: 'closed' } });
    expect(forged.status()).toBe(403);
    expect((await (await request.get(`/api/findings/${visibleId}`)).json()).status).toBe('open');
    const mixed = await analyst.request.post('/api/findings/bulk', { headers: { Origin: origin }, data: { ids: [visibleId, hiddenId], status: 'closed' } });
    expect([403, 404]).toContain(mixed.status());
    expect((await (await request.get(`/api/findings/${visibleId}`)).json()).status).toBe('open');

    await analyst.goto('/findings?project=browser-project&severity=high');
    await analyst.getByRole('checkbox', { name: 'Select Browser finding 001', exact: true }).check();
    await analyst.getByLabel('Bulk status', { exact: true }).selectOption('investigating');
    await analyst.getByLabel('Assignment action').selectOption('assign');
    await analyst.getByLabel('Bulk assignee').fill('scoped-analyst');
    await analyst.getByRole('button', { name: 'Apply to 1 selected' }).click();
    await expect(analyst.getByText('Updated 1 selected findings.', { exact: true })).toBeVisible();
    expect(await (await request.get(`/api/findings/${visibleId}`)).json()).toMatchObject({ status: 'investigating', assignee: 'scoped-analyst' });
    await analyst.getByLabel('View name', { exact: true }).fill('Analyst queue');
    await analyst.getByRole('button', { name: 'Save current filters' }).click();
    await expect(analyst.getByText('View saved.', { exact: true })).toBeVisible();
    expect((await (await request.get('/api/saved-views')).json()).results.map((view: { name: string }) => view.name)).toEqual(['Admin private view']);

    await viewer.goto('/findings?q=Browser%20finding%20001');
    const downloaded = viewer.waitForEvent('download');
    await viewer.getByRole('button', { name: 'Export matching CSV' }).click();
    expect((await downloaded).suggestedFilename()).toBe('secops-findings.csv');
    const csv = await viewer.request.get('/api/findings/export.csv?severity=high');
    expect(csv.status()).toBe(200);
    expect(await csv.text()).toContain('Browser finding 001');
    expect(await csv.text()).not.toContain('Restricted evidence');
    expect((await viewer.request.get('/api/notifications')).status()).toBe(403);
    await analyst.goto('/integrations');
    await expect(analyst.getByRole('button', { name: 'Import Scan Results', exact: true })).toBeVisible();
    await expect(analyst.getByRole('button', { name: 'Notifications', exact: true })).toHaveCount(0);

    await viewer.goto('/profile');
    await viewer.getByLabel('Current password', { exact: true }).fill('Team-browser-password-12345');
    await viewer.getByLabel('New password', { exact: true }).fill('Changed-team-password-45678');
    await viewer.getByLabel('Confirm new password', { exact: true }).fill('Changed-team-password-45678');
    await viewer.getByRole('button', { name: 'Change password and sign out' }).click();
    await expect(viewer.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    expect((await viewer.request.get('/api/auth/me')).status()).toBe(401);
    await analyst.getByRole('button', { name: 'Sign out' }).click();
    await expect(analyst.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
    expect((await analyst.request.get('/api/auth/me')).status()).toBe(401);
  } finally { await viewerContext.close(); await analystContext.close(); }
  await verifyAutomation(page);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
  expect((await request.get('/api/auth/me')).status()).toBe(401);

});
