import { test, expect } from '@playwright/test';

const backend = 'http://127.0.0.1:15101';
test.beforeEach(async ({ request }) => { await request.post(`${backend}/__test/reset`, { data: {} }); });

test('scanner tokens show secrets once, preserve failed drafts and confirm rotation and revocation', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failTokenCreate: 1, failTokenRotate: 1 } });
  await page.addInitScript(() => {
    (window as unknown as { copied: string[] }).copied = [];
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (value: string) => { (window as unknown as { copied: string[] }).copied.push(value); } } });
  });
  await page.goto('/scanner-tokens');
  await page.getByLabel('Token name', { exact: true }).fill('Payments CI');
  await page.getByLabel('Project', { exact: true }).fill('payments');
  await page.getByRole('button', { name: 'Create token', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Token creation temporarily unavailable');
  await expect(page.getByLabel('Token name', { exact: true })).toHaveValue('Payments CI');
  await expect(page.getByLabel('Project', { exact: true })).toHaveValue('payments');
  await page.getByRole('button', { name: 'Create token', exact: true }).click();
  const secret = page.getByRole('textbox', { name: 'New scanner token', exact: true });
  await expect(secret).toHaveValue('scanner-fixture-secret-1');
  expect(await page.evaluate(() => (window as unknown as { copied: string[] }).copied)).toEqual([]);
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage }, url: location.href }))).not.toContain('scanner-fixture-secret');
  await page.getByRole('button', { name: 'Copy token', exact: true }).click();
  expect(await page.evaluate(() => (window as unknown as { copied: string[] }).copied)).toEqual(['scanner-fixture-secret-1']);
  await page.getByRole('button', { name: 'Dismiss token', exact: true }).click();
  await expect(secret).toHaveCount(0);
  await page.reload();
  await expect(secret).toHaveCount(0);
  const card = page.getByRole('article', { name: 'Scanner token Payments CI' });
  await card.getByRole('button', { name: 'Rotate token', exact: true }).click();
  await card.getByRole('button', { name: 'Confirm rotation', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Token rotation temporarily unavailable');
  await expect(card.getByRole('heading', { name: 'Rotate Payments CI?' })).toBeVisible();
  await card.getByRole('button', { name: 'Confirm rotation', exact: true }).click();
  await expect(secret).toHaveValue('scanner-fixture-secret-2');
  await page.getByRole('button', { name: 'Dismiss token', exact: true }).click();
  await card.getByRole('button', { name: 'Revoke token', exact: true }).click();
  await card.getByRole('button', { name: 'Cancel', exact: true }).click();
  let state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.filter((entry: { path: string }) => entry.path.endsWith('/revoke'))).toHaveLength(0);
  await card.getByRole('button', { name: 'Revoke token', exact: true }).click();
  await card.getByRole('button', { name: 'Confirm revocation', exact: true }).click();
  await expect(card.getByText('Revoked', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: 'Rotate token', exact: true }).click();
  await card.getByRole('button', { name: 'Confirm rotation', exact: true }).click();
  await expect(secret).toHaveValue('scanner-fixture-secret-3');
  state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.scannerTokens).toHaveLength(1);
  expect(JSON.stringify(state.scannerTokens)).not.toContain('secret');
});

test('scanner token list retries and unscoped access must be selected explicitly', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failTokenList: 1 } });
  await page.goto('/scanner-tokens');
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Token list temporarily unavailable');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByText('No scanner tokens created yet.', { exact: true })).toBeVisible();
  await page.getByLabel('Token name', { exact: true }).fill('Unscoped scanner');
  await expect(page.getByLabel('Project', { exact: true })).toHaveAttribute('required', '');
  await page.getByLabel('Use no project (unscoped imports only)', { exact: true }).check();
  await expect(page.getByLabel('Project', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Create token', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'New scanner token', exact: true })).toBeVisible();
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.scannerTokens[0].project).toBe('');
});

test('GitHub setup allows mappings without implying credentials or successful imports', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { githubConfigured: false } });
  await page.goto('/github-sync');
  await expect(page.getByRole('region', { name: 'GitHub setup required' })).toContainText('python3 scripts/local.py github-token');
  await page.getByLabel('GitHub repository', { exact: true }).fill('acme/payments');
  await page.getByLabel('Project', { exact: true }).fill('payments');
  await page.getByRole('button', { name: 'Create connection', exact: true }).click();
  const card = page.getByRole('article', { name: 'GitHub connection acme/payments' });
  await expect(card.getByText('queued · Enabled', { exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Sync now', exact: true })).toBeDisabled();
  await card.getByRole('button', { name: 'View history', exact: true }).click();
  await expect(card.getByText('No sync runs recorded yet.', { exact: true })).toBeVisible();
  expect(await page.locator('input[type="password"]').count()).toBe(0);
});

test('GitHub sync recovers failures, distinguishes queued from completed and manages schedules', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failGithubList: 1, failGithubSync: 1, failGithubRuns: 1 } });
  await page.goto('/github-sync');
  await expect(page.getByRole('main').getByRole('alert')).toContainText('GitHub connections temporarily unavailable');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByText('No GitHub connections created yet.', { exact: true })).toBeVisible();
  await page.getByLabel('GitHub repository', { exact: true }).fill('acme/payments');
  await page.getByLabel('Project', { exact: true }).fill('payments');
  await page.getByRole('button', { name: 'Create connection', exact: true }).click();
  const card = page.getByRole('article', { name: 'GitHub connection acme/payments' });
  await expect(card).toBeVisible();
  const state = await (await request.get(`${backend}/__test/state`)).json();
  const id = state.githubConnections[0].id;
  await request.post(`${backend}/__test/github-complete`, { data: { id, error: 'Repository access denied' } });
  await page.getByRole('button', { name: 'Refresh connections', exact: true }).click();
  await expect(card).toContainText('Repository access denied');
  await card.getByRole('button', { name: 'Sync now', exact: true }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('GitHub sync temporarily unavailable');
  await card.getByRole('button', { name: 'Sync now', exact: true }).click();
  await expect(card.getByText('queued · Enabled', { exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Sync now', exact: true })).toBeDisabled();
  await request.post(`${backend}/__test/github-complete`, { data: { id } });
  await page.getByRole('button', { name: 'Refresh connections', exact: true }).click();
  await expect(card.getByText('succeeded · Enabled', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: 'View history', exact: true }).click();
  const history = card.getByRole('region', { name: 'Sync history' });
  await expect(history.getByRole('alert')).toContainText('Sync history temporarily unavailable');
  await history.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(history.getByText('Imported: 1 · New findings: 1 · Updated: 0', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: 'Pause sync', exact: true }).click();
  await expect(card.getByRole('button', { name: 'Sync now', exact: true })).toBeDisabled();
  await card.getByRole('button', { name: 'Edit schedule', exact: true }).click();
  await card.getByLabel('New interval (minutes)', { exact: true }).fill('30');
  await card.getByRole('button', { name: 'Save schedule', exact: true }).click();
  await expect(card).toContainText('Every 30 minutes');
  await card.getByRole('button', { name: 'Enable sync', exact: true }).click();
  await expect(card.getByText('queued · Enabled', { exact: true })).toBeVisible();
});

test('automation pages are admin-only and do not fetch data for analysts', async ({ page, context }) => {
  await context.clearCookies();
  await page.goto('/login');
  await page.getByLabel('Username', { exact: true }).fill('analyst');
  await page.getByLabel('Password', { exact: true }).fill('Regression-password-7S9rY2aK5qW8');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  for (const [path, label] of [['/scanner-tokens', 'Scanner tokens'], ['/github-sync', 'GitHub sync']]) {
    await expect(page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: label, exact: true })).toHaveCount(0);
    const requests: string[] = []; const capture = (request: { url: () => string }) => { if (request.url().endsWith(`/api${path}`)) requests.push(request.url()); };
    page.on('request', capture);
    await page.goto(path);
    await expect(page.getByRole('main').getByRole('alert')).toHaveText('This page is available to administrators.');
    expect(requests).toEqual([]); page.off('request', capture);
    expect((await page.request.get(`/api${path}`)).status()).toBe(403);
  }
});
