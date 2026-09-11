import { expect, request as apiRequest, type Page } from '@playwright/test';

export async function verifyAutomation(page: Page) {
  const origin = 'http://127.0.0.1:15110';
  const machine = await apiRequest.newContext({ baseURL: 'http://127.0.0.1:15111' });
  try {
    await page.goto('/scanner-tokens');
    await page.getByLabel('Token name', { exact: true }).fill('Browser CI');
    await page.getByLabel('Project', { exact: true }).fill('token-project');
    await page.getByLabel('Expires in days', { exact: true }).fill('7');
    await page.getByRole('button', { name: 'Create token', exact: true }).click();
    const secretField = page.getByRole('textbox', { name: 'New scanner token', exact: true });
    await expect(secretField).toBeVisible();
    const firstSecret = await secretField.inputValue();
    const metadataResponse = await page.request.get('/api/scanner-tokens');
    expect(metadataResponse.status()).toBe(200);
    const metadata = await metadataResponse.json();
    expect(metadata.results.find((token: { name: string }) => token.name === 'Browser CI')).toMatchObject({ project: 'token-project', active: true });
    expect(await metadataResponse.text()).not.toContain(firstSecret);
    const scan = (secret: string, project: string) => machine.post('/import/scan', { headers: { 'X-API-Key': secret }, data: { parser: 'generic-json', project, content: JSON.stringify([{ title: 'Scoped scanner evidence', source_id: 'browser-scanner-rule', severity: 'high', asset: 'scanner.example.invalid' }]) } });
    expect((await scan(firstSecret, 'token-project')).status()).toBe(200);
    expect((await scan(firstSecret, 'other-project')).status()).toBe(404);
    expect((await machine.get('/findings', { headers: { 'X-API-Key': firstSecret } })).status()).toBe(401);
    await page.getByRole('button', { name: 'Dismiss token', exact: true }).click();
    await page.reload();
    await expect(secretField).toHaveCount(0);
    const tokenCard = page.getByRole('article', { name: 'Scanner token Browser CI' });
    await tokenCard.getByRole('button', { name: 'Rotate token', exact: true }).click();
    await tokenCard.getByRole('button', { name: 'Confirm rotation', exact: true }).click();
    await expect(secretField).toBeVisible();
    const secondSecret = await secretField.inputValue();
    expect(secondSecret).not.toBe(firstSecret);
    expect((await scan(firstSecret, 'token-project')).status()).toBe(401);
    expect((await scan(secondSecret, 'token-project')).status()).toBe(200);
    await page.getByRole('button', { name: 'Dismiss token', exact: true }).click();
    await tokenCard.getByRole('button', { name: 'Revoke token', exact: true }).click();
    await tokenCard.getByRole('button', { name: 'Confirm revocation', exact: true }).click();
    await expect(tokenCard.getByText('Revoked', { exact: true })).toBeVisible();
    expect((await scan(secondSecret, 'token-project')).status()).toBe(401);
    expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage }, url: location.href }))).not.toContain(secondSecret);
  } finally { await machine.dispose(); }

  // This server uses a tests-only GitHub client fixture; no request reaches GitHub.
  await page.goto('/github-sync');
  await expect(page.getByRole('region', { name: 'GitHub setup required' })).toHaveCount(0);
  await page.getByLabel('GitHub repository', { exact: true }).fill('fixture/browser-repository');
  await page.getByLabel('Project', { exact: true }).fill('github-browser-project');
  await page.getByLabel('Sync interval (minutes)', { exact: true }).fill('30');
  await page.getByRole('button', { name: 'Create connection', exact: true }).click();
  const card = page.getByRole('article', { name: 'GitHub connection fixture/browser-repository' });
  await expect(card).toBeVisible();
  const connection = (await (await page.request.get('/api/github-sync')).json()).results.find((item: { repository: string }) => item.repository === 'fixture/browser-repository');
  const waitForSync = async () => {
    await expect.poll(async () => (await (await page.request.get('/api/github-sync')).json()).results.find((item: { id: string }) => item.id === connection.id).status, { timeout: 15000 }).toBe('succeeded');
    await page.getByRole('button', { name: 'Refresh connections', exact: true }).click();
    await expect(card.getByText('succeeded · Enabled', { exact: true })).toBeVisible();
  };
  await waitForSync();
  const imported = (await (await page.request.get('/api/findings?project=github-browser-project')).json()).results;
  expect(imported.length).toBeGreaterThan(0);
  expect(imported.every((finding: { project: string }) => finding.project === 'github-browser-project')).toBe(true);
  await card.getByRole('button', { name: 'View history', exact: true }).click();
  await expect(card.getByRole('region', { name: 'Sync history' })).toContainText('succeeded');
  await card.getByRole('button', { name: 'Pause sync', exact: true }).click();
  await expect(card.getByRole('button', { name: 'Enable sync', exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Sync now', exact: true })).toBeDisabled();
  expect((await page.request.post(`/api/github-sync/${connection.id}/sync`, { headers: { Origin: origin }, data: {} })).status()).toBe(409);
  await card.getByRole('button', { name: 'Edit schedule', exact: true }).click();
  await card.getByLabel('New interval (minutes)', { exact: true }).fill('120');
  await card.getByRole('button', { name: 'Save schedule', exact: true }).click();
  await expect(card).toContainText('Every 120 minutes');
  await card.getByRole('button', { name: 'Enable sync', exact: true }).click();
  await waitForSync();
  const runsBefore = (await (await page.request.get(`/api/github-sync/${connection.id}/runs`)).json()).results.length;
  await card.getByRole('button', { name: 'Sync now', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: /^Sync queued\./ })).toBeVisible();
  await waitForSync();
  expect((await (await page.request.get(`/api/github-sync/${connection.id}/runs`)).json()).results.length).toBeGreaterThan(runsBefore);
  const after = (await (await page.request.get('/api/findings?project=github-browser-project')).json()).results;
  expect(after).toHaveLength(imported.length);
}
