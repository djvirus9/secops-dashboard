import { test, expect } from '@playwright/test';

const fixtures = Array.from({ length: 121 }, (_, index) => ({
  title: `Browser finding ${String(index + 1).padStart(3, '0')}`,
  source_id: `browser-rule-${index + 1}`, severity: index === 0 ? 'high' : 'low',
  asset: 'browser.example.invalid', file_path: 'src/review.py', line_number: index + 1,
  description: 'Evidence from an isolated browser regression', recommendation: 'Apply the fixture fix',
}));

test('migrated backend supports import, triage, rediscovery, asset risk updates and history', async ({ page, request }) => {
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
  await expect(page.getByRole('status')).toHaveText('1–50 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('51–100 of 121');
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('101–121 of 121');
  await page.getByLabel('Search findings').fill('Browser finding 001');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('status')).toHaveText('1–1 of 1');
  await page.getByRole('link', { name: 'Browser finding 001', exact: true }).click();
  const detailUrl = page.url();
  await expect(page.getByText('Evidence from an isolated browser regression', { exact: true })).toBeVisible();
  await page.getByRole('textbox', { name: 'Comment', exact: true }).fill('Confirmed by the browser regression');
  await page.getByRole('button', { name: 'Add Comment', exact: true }).click();
  await expect(page.getByText('Confirmed by the browser regression', { exact: true })).toBeVisible();
  await page.getByLabel('Status', { exact: true }).selectOption('resolved');
  await page.getByRole('button', { name: 'Update Finding', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('Finding updated.');
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
});
