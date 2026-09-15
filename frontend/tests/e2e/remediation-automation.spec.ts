import { test, expect, type Page } from '@playwright/test';

const backend = 'http://127.0.0.1:15101';
const findingId = '00000001-1111-4111-8111-111111111111';
const teamId = '00000001-5555-4555-8555-555555555555';
const analystId = '00000098-1111-4111-8111-111111111111';
const reviewerId = '00000099-1111-4111-8111-111111111111';
test.beforeEach(async ({ request }) => { await request.post(`${backend}/__test/reset`, { data: {} }); });

function latch() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

/** Hold one actual rule response, independently of the eligible-assignee read. */
async function holdNextRuleResponse(page: Page, project: string) {
  const arrived = latch();
  const released = latch();
  let held = false;
  await page.route('**/api/ownership/rules?*', async route => {
    const request = route.request();
    if (held || request.method() !== 'GET' || new URL(request.url()).searchParams.get('project') !== project) {
      await route.continue();
      return;
    }
    held = true;
    const response = await route.fetch();
    arrived.resolve();
    await released.promise;
    await route.fulfill({ response });
  });
  return { arrived: arrived.promise, release: released.resolve };
}

function waitForRuleSave(page: Page, project: string) {
  return page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/api/ownership/rules' && url.searchParams.get('project') === project
      && response.request().method() === 'PUT';
  });
}

test('ownership fields wait for the selected rule even when eligible assignees load first', async ({ page, request }) => {
  const held = await holdNextRuleResponse(page, 'payments');
  try {
    await page.goto('/catalog');
    await page.getByLabel('Routing project').selectOption('payments');
    await held.arrived;
    const assignee = page.getByLabel('Default assignee');
    const enabled = page.getByLabel('Enable ownership routing for this project');
    const save = page.getByRole('button', { name: 'Save routing', exact: true });
    // The options prove the independent assignee request has finished. A slow
    // rule response must still prevent editing fields that it will hydrate.
    await expect(assignee.locator('option[value="reviewer"]')).toHaveCount(1);
    await expect(assignee).toBeDisabled();
    await expect(enabled).toBeDisabled();
    await expect(save).toBeDisabled();
    held.release();
    await expect(save).toBeEnabled();
    await assignee.selectOption('reviewer');
    await enabled.check();
    const saved = waitForRuleSave(page, 'payments');
    await save.click();
    const response = await saved;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual({ enabled: true, default_assignee: 'reviewer' });
    await expect(page.getByText('Ownership routing saved. Existing manual assignments are preserved.')).toBeVisible();
    await expect(save).toBeEnabled();
    await expect(assignee).toHaveValue('reviewer');
    await expect(enabled).toBeChecked();
    const state = await (await request.get(`${backend}/__test/state`)).json();
    expect(state.v06.rules).toContainEqual(expect.objectContaining({ project: 'payments', enabled: true, default_assignee: 'reviewer' }));
  } finally { held.release(); }
});

test('membership-triggered rule refresh preserves an unsaved ownership draft', async ({ page, request }) => {
  await page.goto('/catalog');
  await page.getByLabel('Manage team').selectOption(teamId);
  await expect(page.getByRole('button', { name: 'Remove reviewer from team' })).toBeVisible();
  await page.getByLabel('Routing project').selectOption('payments');
  const assignee = page.getByLabel('Default assignee');
  const enabled = page.getByLabel('Enable ownership routing for this project');
  const save = page.getByRole('button', { name: 'Save routing', exact: true });
  await expect(save).toBeEnabled();
  await assignee.selectOption('reviewer');
  await enabled.check();
  const held = await holdNextRuleResponse(page, 'payments');
  try {
    await page.getByLabel('Add team member').selectOption(analystId);
    await page.getByRole('button', { name: 'Add member', exact: true }).click();
    await held.arrived;
    await expect(page.getByText('Team member added. Project grants are unchanged.')).toBeVisible();
    await expect(save).toBeDisabled();
    await expect(assignee).toHaveValue('reviewer');
    await expect(enabled).toBeChecked();
    held.release();
    await expect(save).toBeEnabled();
    await expect(assignee).toHaveValue('reviewer');
    await expect(enabled).toBeChecked();
    const saved = waitForRuleSave(page, 'payments');
    await save.click();
    const response = await saved;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual({ enabled: true, default_assignee: 'reviewer' });
    const state = await (await request.get(`${backend}/__test/state`)).json();
    expect(state.v06.members[teamId]).toContain(analystId);
    expect(state.v06.rules).toContainEqual(expect.objectContaining({ project: 'payments', enabled: true, default_assignee: 'reviewer' }));
  } finally { held.release(); }
});

test('changing routing project hydrates its rule without carrying over another project draft', async ({ page }) => {
  await page.goto('/catalog');
  await page.getByLabel('Project key', { exact: true }).fill('identity');
  await page.getByRole('combobox', { name: 'Owning team', exact: true }).selectOption(teamId);
  await page.getByRole('button', { name: 'Create project profile', exact: true }).click();
  await expect(page.getByText('Project profile created.', { exact: true })).toBeVisible();
  await page.getByLabel('Routing project').selectOption('payments');
  const assignee = page.getByLabel('Default assignee');
  const enabled = page.getByLabel('Enable ownership routing for this project');
  const save = page.getByRole('button', { name: 'Save routing', exact: true });
  await expect(save).toBeEnabled();
  await assignee.selectOption('reviewer');
  await enabled.check();
  const held = await holdNextRuleResponse(page, 'identity');
  try {
    await page.getByLabel('Routing project').selectOption('identity');
    await held.arrived;
    await expect(assignee.locator('option[value="reviewer"]')).toHaveCount(1);
    await expect(assignee).toBeDisabled();
    await expect(enabled).toBeDisabled();
    await expect(save).toBeDisabled();
    held.release();
    await expect(save).toBeEnabled();
    await expect(assignee).toHaveValue('');
    await expect(enabled).not.toBeChecked();
    const saved = waitForRuleSave(page, 'identity');
    await save.click();
    const response = await saved;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual({ enabled: false, default_assignee: null });
  } finally { held.release(); }
});

test('ownership rule read failure blocks editing until a successful retry', async ({ page }) => {
  let failNextRead = true;
  await page.route('**/api/ownership/rules?*', async route => {
    if (failNextRead && route.request().method() === 'GET') {
      failNextRead = false;
      await route.fulfill({ status: 503, json: { detail: 'Ownership rule temporarily unavailable' } });
    } else await route.continue();
  });
  await page.goto('/catalog');
  await page.getByLabel('Routing project').selectOption('payments');
  const assignee = page.getByLabel('Default assignee');
  const enabled = page.getByLabel('Enable ownership routing for this project');
  const save = page.getByRole('button', { name: 'Save routing', exact: true });
  await expect(page.getByRole('main').getByRole('alert')).toContainText('Ownership rule temporarily unavailable');
  await expect(assignee.locator('option[value="reviewer"]')).toHaveCount(1);
  await expect(assignee).toBeDisabled();
  await expect(enabled).toBeDisabled();
  await expect(save).toBeDisabled();
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(save).toBeEnabled();
  await expect(assignee).toHaveValue('');
  await expect(enabled).not.toBeChecked();
  await assignee.selectOption('reviewer');
  await enabled.check();
  const saved = waitForRuleSave(page, 'payments');
  await save.click();
  const response = await saved;
  expect(response.status()).toBe(200);
  expect(response.request().postDataJSON()).toEqual({ enabled: true, default_assignee: 'reviewer' });
});

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
