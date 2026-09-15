import { test, expect } from '@playwright/test';

const backend = 'http://127.0.0.1:15101';
const findingId = '00000001-1111-4111-8111-111111111111';
const teamId = '00000001-5555-4555-8555-555555555555';
const analystId = '00000098-1111-4111-8111-111111111111';
const reviewerId = '00000099-1111-4111-8111-111111111111';
test.beforeEach(async ({ request }) => { await request.post(`${backend}/__test/reset`, { data: {} }); });

test('team membership and opt-in ownership routing preserve the grant boundary', async ({ page, request }) => {
  await page.goto('/catalog');
  await expect(page.getByRole('heading', { name: 'Ownership routing', exact: true })).toBeVisible();
  await page.getByLabel('Manage team').selectOption(teamId);
  await expect(page.getByRole('button', { name: 'Remove reviewer from team' })).toBeVisible();
  await page.getByLabel('Add team member').selectOption(analystId);
  await page.getByRole('button', { name: 'Add member', exact: true }).click();
  await expect(page.getByText('Team member added. Project grants are unchanged.')).toBeVisible();
  await page.getByLabel('Routing project').selectOption('payments');
  await expect(page.getByLabel('Enable ownership routing for this project')).not.toBeChecked();
  await page.getByLabel('Default assignee').selectOption('analyst');
  await page.getByLabel('Enable ownership routing for this project').check();
  await page.getByRole('button', { name: 'Save routing', exact: true }).click();
  await expect(page.getByText('Ownership routing saved. Existing manual assignments are preserved.')).toBeVisible();
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.v06.members[teamId]).toContain(analystId);
  expect(state.v06.rules[0]).toMatchObject({ project: 'payments', enabled: true, default_assignee: 'analyst' });
  expect(state.requests.findLast((row: { path: string }) => row.path === '/ownership/rules').hasApiKey).toBe(false);
  await page.getByRole('button', { name: 'Remove analyst from team' }).click();
  await expect(page.getByText('Team member removed. Project grants are unchanged.')).toBeVisible();
});

test('eligible assignee selection recovers from read failure and retains legacy ownership', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { legacyAssignee: true, failAssignees: 1 } });
  await page.goto(`/findings/${findingId}`);
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Eligible accounts temporarily unavailable');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByLabel('Assignee', { exact: true })).toHaveValue('departed-owner');
  await expect(page.getByText('The stored assignee is retained.', { exact: false })).toBeVisible();
  await expect(page.getByLabel('Assignee', { exact: true }).locator('option[value="viewer"]')).toHaveCount(0);
  await page.getByLabel('Assignee', { exact: true }).selectOption('analyst');
  await page.getByRole('button', { name: 'Update Finding' }).click();
  await expect(page.getByText('Finding updated.', { exact: true })).toBeVisible();
  expect((await (await request.get(`${backend}/__test/state`)).json()).findings[0].assignee).toBe('analyst');
});

test('team and unassigned queues surface invalid legacy owners without hiding work', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { legacyAssignee: true } });
  await page.goto('/my-queue');
  await page.getByRole('button', { name: 'Unassigned', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Unassigned queue' })).toBeVisible();
  await expect(page.getByText('Needs reassignment')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Finding 1', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Team work' }).click();
  await page.getByLabel('Queue team').selectOption(teamId);
  await expect(page.getByRole('heading', { name: 'Team queue' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Finding 1', exact: true })).toBeVisible();
});

test('bulk assignment uses eligible accounts rather than free text', async ({ page, request }) => {
  await page.goto('/findings');
  await page.getByLabel('Select Finding 1', { exact: true }).check();
  await page.getByLabel('Assignment action').selectOption('assign');
  await page.getByLabel('Bulk assignee').selectOption('analyst');
  await page.getByRole('button', { name: 'Apply to 1 selected' }).click();
  await expect(page.getByText('Updated 1 selected findings.')).toBeVisible();
  expect((await (await request.get(`${backend}/__test/state`)).json()).findings[0].assignee).toBe('analyst');
});

test('operations policy failure preserves edits and acknowledgment suppresses reminders', async ({ page, request }) => {
  await request.post(`${backend}/__test/reset`, { data: { failAutomationSave: 1 } });
  await page.goto('/operations');
  await expect(page.getByRole('heading', { name: 'Operations inbox' })).toBeVisible();
  await expect(page.getByLabel('Enable operations policy')).not.toBeChecked();
  await expect(page.getByLabel('Send reminders to the configured Slack channel')).not.toBeChecked();
  await page.getByLabel('Policy project', { exact: true }).fill('payments');
  await page.getByLabel('SLA warning lead time (hours)').fill('48');
  await page.getByLabel('Enable operations policy').check();
  await page.getByRole('button', { name: 'Save operations policy' }).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Operations policy save temporarily unavailable');
  await expect(page.getByLabel('Policy project', { exact: true })).toHaveValue('payments');
  await page.getByRole('button', { name: 'Save operations policy' }).click();
  await expect(page.getByText('Operations policy saved.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Evaluate payments' }).click();
  await expect(page.getByText('Evaluation queued.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Acknowledge Overdue remediation: Finding 1' }).click();
  await expect(page.getByText('Acknowledged by reviewer', { exact: false })).toBeVisible();
  const state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.v06.policies[0]).toMatchObject({ project: 'payments', warn_before_hours: 48, enabled: true, notify_slack: false });
  expect(state.v06.alerts[0].state).toBe('acknowledged');
});

test('Jira mappings and one-field pushes require explicit review and confirmation', async ({ page, request }) => {
  await page.goto('/jira-sync');
  await page.getByLabel('Dashboard account').selectOption(reviewerId);
  await page.getByLabel('Jira account ID').fill('fixture-account');
  await page.getByRole('button', { name: 'Save Jira mapping' }).click();
  await expect(page.getByText('Jira account mapping saved.')).toBeVisible();
  await page.goto(`/findings/${findingId}`);
  await expect(page.getByRole('heading', { name: 'Jira remediation progress' })).toBeVisible();
  await expect(page.getByText('A Jira transition to Done requests verification.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Review assignee push' }).click();
  await expect(page.getByRole('button', { name: 'Queue Jira update' })).toBeDisabled();
  let state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.filter((row: { path: string }) => row.path.endsWith('/jira/push'))).toHaveLength(0);
  await page.getByLabel('I confirm this update to the linked Jira issue.').check();
  await page.getByRole('button', { name: 'Queue Jira update' }).click();
  await expect(page.getByText('Explicit Jira update queued. No finding was marked fixed.')).toBeVisible();
  state = await (await request.get(`${backend}/__test/state`)).json();
  expect(state.requests.findLast((row: { path: string }) => row.path.endsWith('/jira/push')).body).toMatchObject({ field: 'assignee', expected_local_status: 'open', expected_local_assignee: 'reviewer', expected_remote_updated_at: '2026-01-03T00:00:00Z' });
  expect(state.findings[0].status).toBe('open');
});

test('viewer sees scoped operations context without mutation or administrator controls', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await page.getByLabel('Username', { exact: true }).fill('viewer');
  await page.getByLabel('Password', { exact: true }).fill('Regression-password-7S9rY2aK5qW8');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.goto('/operations');
  await expect(page.getByRole('heading', { name: 'Operations inbox' })).toBeVisible();
  await expect(page.getByRole('button', { name: /Acknowledge/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Save operations policy' })).toHaveCount(0);
  await expect(page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Jira sync' })).toHaveCount(0);
  await page.goto(`/findings/${findingId}`);
  await expect(page.getByRole('heading', { name: 'Jira remediation progress' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Pull Jira progress' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Review .* push/ })).toHaveCount(0);
});
