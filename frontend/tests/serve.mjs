// Isolated synthetic API. All browser traffic still traverses the real production proxy.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { cp } from 'node:fs/promises';
await cp('public', '.next/standalone/public', { recursive: true });
await cp('.next/static', '.next/standalone/.next/static', { recursive: true });

const userId = '00000099-1111-4111-8111-111111111111';
const users = { reviewer: { id: userId, username: 'reviewer', role: 'admin', projects: null, active: true }, analyst: { id: '00000098-1111-4111-8111-111111111111', username: 'analyst', role: 'analyst', projects: ['payments'], active: true }, viewer: { id: '00000097-1111-4111-8111-111111111111', username: 'viewer', role: 'viewer', projects: ['payments'], active: true } };
let sessions = new Map([['regression-session', users.reviewer]]);
let savedViews = [];
let nextView = 1;
const password = 'Regression-password-7S9rY2aK5qW8';
const finding = (index) => ({
  id: `${index.toString(16).padStart(8, '0')}-1111-4111-8111-111111111111`,
  fingerprint: `fixture-${index}`, tool: 'bandit', title: `Finding ${index}`, severity: 'high',
  asset: 'src/app.py', project: 'payments', asset_id: null, exposure: 'internal', criticality: 'medium',
  status: 'open', assignee: index === 1 ? 'reviewer' : null, risk_score: 70, occurrences: 1, description: 'Synthetic regression evidence',
  priority_score: index === 1 ? 85 : 30,
  priority_reasons: [{ factor: 'High severity', points: 30 }],
  recommendation: 'Synthetic regression recommendation', cwe_id: 79,
  cve_id: index === 1 ? 'CVE-2026-10001' : null, cvss_score: 7.1,
  kev: index === 1, kev_date_added: index === 1 ? '2026-01-01' : null,
  kev_due_date: index === 1 ? '2026-01-08' : null, kev_ransomware: false,
  epss_score: null, epss_percentile: null, intelligence_updated_at: null,
  component: 'fixture-package', component_version: '1.0', file_path: 'src/app.py', line_number: index,
  references: ['javascript:alert(1)', 'https://security.invalid/advisory'], tags: ['fixture'],
  first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-02T00:00:00Z', signal_id: 'fixture', comments: [],
  remediation_due_at: '2099-01-31T00:00:00Z', resolved_at: null, sla_status: 'on_track',
  risk_acceptance: { status: 'none', accepted_at: null, expires_at: null, accepted_by: null, reason: null },
  workflow: { disposition_reason: null, duplicate_of_id: null, verification_requested_at: null, verified_at: null, verified_by: null },
});
const asset = (index) => ({ id: String(index), project: 'payments', key: `asset-${index}.invalid`, name: `Asset ${index}`, owner: 'security', environment: 'prod', criticality: 'medium', exposure: 'internal', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' });
let state;
function reset() { sessions = new Map([['regression-session', users.reviewer]]); savedViews = []; nextView = 1; state = { findings: Array.from({ length: 121 }, (_, index) => finding(index + 1)), assets: Array.from({ length: 121 }, (_, index) => asset(index + 1)), requests: [], failPatch: 0, failIntegrations: 0, failSummary: 0, failFindings: 0, scannerTokens: [], tokenVersion: 0, githubConfigured: true, githubConnections: [], githubRuns: {}, teams: [{ id: '00000001-5555-4555-8555-555555555555', name: 'Platform Security', contact: '#platform-security', active: true }], projects: [{ name: 'payments', display_name: 'Payments', team_id: '00000001-5555-4555-8555-555555555555', team_name: 'Platform Security', business_unit: 'Commerce', tier: 'critical', repository_url: 'https://github.com/example/payments', active: true }], coverage: [{ id: '00000001-6666-4666-8666-666666666666', project: 'payments', team: 'Platform Security', source_type: 'scanner', source: 'bandit', interval_hours: 24, required: true, enabled: true, health: 'healthy', last_status: 'completed', last_successful_at: '2026-01-02T00:00:00Z', last_clean_at: '2026-01-02T00:00:00Z', last_findings: 0, next_due_at: '2099-01-03T00:00:00Z' }], auditEvents: [{ id: '00000001-7777-4777-8777-777777777777', actor: 'reviewer', action: 'finding.update', object_type: 'finding', object_id: '00000001-1111-4111-8111-111111111111', details: { fields: ['status'] }, created_at: '2026-01-02T00:00:00Z' }], intelligence: [{ source: 'cisa_kev', enabled: false, interval_hours: 24, status: 'idle', record_count: 1, last_synced_at: null, next_sync_at: '2099-01-01T00:00:00Z', stale: true, last_error: null }, { source: 'first_epss', enabled: false, interval_hours: 24, status: 'succeeded', record_count: 120, last_synced_at: '2026-01-02T00:00:00Z', next_sync_at: '2099-01-01T00:00:00Z', stale: false, last_error: null }], policies: [{ project: '', critical_days: 7, high_days: 30, medium_days: 90, low_days: 180, info_days: 365, kev_days: 7, updated_at: '2026-01-02T00:00:00Z' }] }; }
reset();
const send = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:15101');
  let content = ''; for await (const chunk of req) content += chunk;
  let body; try { body = content ? JSON.parse(content) : {}; } catch { return send(res, 400, { detail: 'Invalid JSON' }); }
  if (url.pathname === '/__test/reset') { reset(); Object.assign(state, body); return send(res, 200, { ok: true }); }
  if (url.pathname === '/__test/state') return send(res, 200, state);
  if (url.pathname === '/__test/github-complete') {
    const connection = state.githubConnections.find(item => item.id === body.id);
    connection.status = body.error ? 'failed' : 'succeeded'; connection.last_error = body.error || null; connection.last_synced_at = '2026-01-02T00:00:00Z';
    (state.githubRuns[connection.id] ||= []).unshift({ id: `run-${state.githubRuns[connection.id].length + 1}`, status: connection.status, started_at: '2026-01-02T00:00:00Z', completed_at: '2026-01-02T00:00:01Z', imported: body.error ? 0 : 1, new_findings: body.error ? 0 : 1, updated: 0, error: body.error || null });
    return send(res, 200, { ok: true });
  }
  const token = /(?:^|;\s*)secops_session=([^;]+)/.exec(req.headers.cookie || '')?.[1];
  const user = sessions.get(token);
  if (url.pathname === '/__test/expire') { sessions.clear(); return send(res, 200, { ok: true }); }
  if (url.pathname === '/auth/login') {
    const account = users[body.username];
    if (!account || body.password !== password) return send(res, 401, { detail: 'Invalid username or password' });
    const session = `session-${body.username}`; sessions.set(session, account);
    res.setHeader('Set-Cookie', `secops_session=${session}; Path=/; HttpOnly; SameSite=Strict`);
    return send(res, 200, { user: account, expires_at: '2099-01-01T00:00:00Z' });
  }
  if (!user) return send(res, 401, { detail: 'Sign in required' });
  if (url.pathname === '/auth/me') return send(res, 200, { user });
  if (url.pathname === '/auth/logout') { sessions.delete(token); res.setHeader('Set-Cookie', 'secops_session=; Path=/; Max-Age=0'); return send(res, 200, { ok: true }); }
  if (url.pathname === '/auth/password') { sessions.clear(); res.setHeader('Set-Cookie', 'secops_session=; Path=/; Max-Age=0'); return send(res, 200, { ok: true }); }
  if (user.role !== 'admin' && ['/users', '/integrations', '/notifications', '/scanner-tokens', '/github-sync', '/audit-events'].some(path => url.pathname === path || url.pathname.startsWith(`${path}/`))) return send(res, 403, { detail: 'Administrator required' });
  if (user.role !== 'admin' && req.method !== 'GET' && url.pathname.startsWith('/coverage')) return send(res, 403, { detail: 'Administrator required' });
  if (user.role !== 'admin' && req.method !== 'GET' && url.pathname.startsWith('/catalog')) return send(res, 403, { detail: 'Administrator required' });
  if (user.role !== 'admin' && req.method !== 'GET' && ['/intelligence', '/remediation'].some(path => url.pathname === path || url.pathname.startsWith(`${path}/`))) return send(res, 403, { detail: 'Administrator required' });
  if (user.role !== 'admin' && url.pathname.endsWith('/risk-acceptance')) return send(res, 403, { detail: 'Administrator required' });
  if (user.role === 'viewer' && req.method !== 'GET' && !url.pathname.startsWith('/saved-views')) return send(res, 403, { detail: 'Read-only account' });
  state.requests.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), method: req.method, body, actor: user.username, hasAuthorization: Boolean(req.headers.authorization), hasApiKey: Boolean(req.headers['x-api-key']), hasSpoofedUser: Boolean(req.headers['x-secops-user']) });
  if (url.pathname === '/catalog') {
    const projects = user.projects === null ? state.projects : state.projects.filter(project => user.projects.includes(project.name));
    const teamIds = new Set(projects.map(project => project.team_id).filter(Boolean));
    const teams = user.projects === null ? state.teams : state.teams.filter(team => teamIds.has(team.id));
    const unmanaged = user.projects === null || user.projects.includes('unmanaged-service') ? ['unmanaged-service'] : [];
    return send(res, 200, { teams, projects, unmanaged_projects: unmanaged });
  }
  if (url.pathname === '/catalog/teams') {
    const team = { id: `${String(state.teams.length + 1).padStart(8, '0')}-5555-4555-8555-555555555555`, ...body, active: true };
    state.teams.push(team); return send(res, 201, { team });
  }
  if (url.pathname === '/catalog/projects') {
    const team = state.teams.find(item => item.id === body.team_id);
    const project = { ...body, team_name: team?.name || null, active: true };
    state.projects.push(project); return send(res, 201, { project });
  }
  if (url.pathname.startsWith('/catalog/teams/')) {
    const team = state.teams.find(item => item.id === url.pathname.split('/')[3]); Object.assign(team, body); return send(res, 200, { team });
  }
  if (url.pathname.startsWith('/catalog/projects/')) {
    const project = state.projects.find(item => item.name === decodeURIComponent(url.pathname.split('/')[3])); Object.assign(project, body); return send(res, 200, { project });
  }
  if (url.pathname === '/coverage') {
    if (req.method === 'GET') {
      let rows = state.coverage; if (user.projects !== null) rows = rows.filter(row => user.projects.includes(row.project));
      const health = Object.fromEntries(['healthy', 'stale', 'failing', 'missing', 'disabled'].map(name => [name, rows.filter(row => row.health === name).length]));
      return send(res, 200, { count: rows.length, required_attention: rows.filter(row => row.required && row.enabled && row.health !== 'healthy').length, health, results: rows, generated_at: '2026-01-02T00:00:00Z' });
    }
    const expectation = { id: `${String(state.coverage.length + 1).padStart(8, '0')}-6666-4666-8666-666666666666`, ...body, team: null, enabled: true, health: 'missing', last_status: null, last_successful_at: null, last_clean_at: null, last_findings: null, next_due_at: null };
    state.coverage.push(expectation); return send(res, 201, { expectation });
  }
  if (url.pathname.startsWith('/coverage/')) {
    const expectation = state.coverage.find(item => item.id === url.pathname.split('/')[2]); Object.assign(expectation, body); expectation.health = expectation.enabled ? 'healthy' : 'disabled'; return send(res, 200, { expectation });
  }
  if (url.pathname === '/audit-events') {
    let rows = state.auditEvents;
    for (const key of ['actor', 'action', 'object_type']) if (url.searchParams.get(key)) rows = rows.filter(row => row[key].includes(url.searchParams.get(key)));
    const offset = Number(url.searchParams.get('offset') || 0), limit = Number(url.searchParams.get('limit') || 50);
    return send(res, 200, { count: rows.length, page_count: rows.slice(offset, offset + limit).length, offset, results: rows.slice(offset, offset + limit) });
  }
  if (url.pathname === '/my-queue') {
    let rows = state.findings.filter(row => row.assignee === user.username && ['open', 'investigating', 'verification_pending'].includes(row.status));
    if (user.projects !== null) rows = rows.filter(row => user.projects.includes(row.project));
    const offset = Number(url.searchParams.get('offset') || 0), limit = Number(url.searchParams.get('limit') || 50);
    return send(res, 200, { count: rows.length, overdue: 0, page_count: rows.slice(offset, offset + limit).length, offset, results: rows.slice(offset, offset + limit) });
  }
  if (url.pathname === '/scanner-tokens') {
    if (req.method === 'GET') {
      if (state.failTokenList-- > 0) return send(res, 503, { detail: 'Token list temporarily unavailable' });
      return send(res, 200, { count: state.scannerTokens.length, results: state.scannerTokens });
    }
    if (state.failTokenCreate-- > 0) return send(res, 503, { detail: 'Token creation temporarily unavailable' });
    const token = { id: `${String(state.scannerTokens.length + 1).padStart(8, '0')}-3333-4333-8333-333333333333`, name: body.name, project: body.project, created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', revoked_at: null, last_used_at: null, active: true };
    state.scannerTokens.unshift(token);
    return send(res, 201, { token: `scanner-fixture-secret-${++state.tokenVersion}`, scanner_token: token });
  }
  if (url.pathname.startsWith('/scanner-tokens/')) {
    const token = state.scannerTokens.find(item => item.id === url.pathname.split('/')[2]);
    if (!token) return send(res, 404, { detail: 'Token not found' });
    if (url.pathname.endsWith('/rotate')) {
      if (state.failTokenRotate-- > 0) return send(res, 503, { detail: 'Token rotation temporarily unavailable' });
      Object.assign(token, { active: true, revoked_at: null, last_used_at: null });
      return send(res, 201, { token: `scanner-fixture-secret-${++state.tokenVersion}`, scanner_token: token });
    }
    Object.assign(token, { active: false, revoked_at: '2026-01-02T00:00:00Z' }); return send(res, 200, { ok: true });
  }
  if (url.pathname === '/github-sync') {
    if (req.method === 'GET') {
      if (state.failGithubList-- > 0) return send(res, 503, { detail: 'GitHub connections temporarily unavailable' });
      return send(res, 200, { configured: state.githubConfigured, count: state.githubConnections.length, results: state.githubConnections });
    }
    const connection = { id: `${String(state.githubConnections.length + 1).padStart(8, '0')}-4444-4444-8444-444444444444`, ...body, enabled: true, status: 'queued', next_sync_at: '2026-01-01T00:00:00Z', last_synced_at: null, last_error: null };
    state.githubConnections.unshift(connection); return send(res, 201, { connection });
  }
  if (url.pathname.startsWith('/github-sync/')) {
    const connection = state.githubConnections.find(item => item.id === url.pathname.split('/')[2]);
    if (!connection) return send(res, 404, { detail: 'GitHub connection not found' });
    if (url.pathname.endsWith('/runs')) {
      if (state.failGithubRuns-- > 0) return send(res, 503, { detail: 'Sync history temporarily unavailable' });
      return send(res, 200, { results: state.githubRuns[connection.id] || [] });
    }
    if (url.pathname.endsWith('/sync')) {
      if (state.failGithubSync-- > 0) return send(res, 503, { detail: 'GitHub sync temporarily unavailable' });
      if (!state.githubConfigured) return send(res, 503, { detail: 'GitHub access is not configured' });
      if (!connection.enabled || ['queued', 'syncing'].includes(connection.status)) return send(res, 409, { detail: 'Connection is paused or busy' });
      connection.status = 'queued'; return send(res, 202, { ok: true, message: 'Sync queued' });
    }
    Object.assign(connection, body); if ('enabled' in body) connection.status = body.enabled ? 'queued' : 'idle';
    return send(res, 200, { connection });
  }
  if (url.pathname === '/saved-views') {
    if (req.method === 'GET') return send(res, 200, { results: savedViews.filter(view => view.owner === user.id) });
    const view = { id: `${String(nextView++).padStart(8, '0')}-2222-4222-8222-222222222222`, ...body, owner: user.id }; savedViews.push(view); return send(res, 200, view);
  }
  if (url.pathname.startsWith('/saved-views/')) {
    const view = savedViews.find(view => view.id === url.pathname.split('/')[2] && view.owner === user.id);
    if (!view) return send(res, 404, { detail: 'Saved view not found' });
    if (req.method === 'DELETE') { savedViews = savedViews.filter(item => item !== view); res.writeHead(204); return res.end(); }
    Object.assign(view, body); return send(res, 200, view);
  }
  if (url.pathname === '/findings/bulk') {
    if (state.failBulk-- > 0) return send(res, 503, { detail: 'Bulk update temporarily unavailable' });
    for (const row of state.findings.filter(row => body.ids.includes(row.id))) {
      if (body.status) row.status = body.status;
      if ('assignee' in body) row.assignee = body.assignee || null;
    }
    return send(res, 200, { ok: true, updated: body.ids.length });
  }
  if (url.pathname === '/users') {
    if (req.method === 'GET') return send(res, 200, { results: Object.values(users) });
    const account = { id: '00000096-1111-4111-8111-111111111111', ...body, active: true }; users[account.username] = account; return send(res, 200, { user: account });
  }
  if (url.pathname.startsWith('/users/')) {
    const account = Object.values(users).find(user => user.id === url.pathname.split('/')[2]);
    Object.assign(account, body); return send(res, 200, { user: account });
  }
  if (url.pathname === '/health') return send(res, 200, { status: 'ok' });
  if (url.pathname === '/dashboard/summary') {
    if (state.failSummary-- > 0) return send(res, 503, { detail: 'Summary unavailable' });
    return send(res, 200, { total_findings: 121, active_findings: 121, resolved_findings: 0, critical_findings: 1, assets: 121, active_by_severity: { high: 120 }, urgent_findings: 1, known_exploited_findings: 1, aging_buckets: { '0_7_days': 0, '8_30_days': 0, '31_90_days': 0, over_90_days: 121 }, priority_buckets: { urgent: 1, high: 0, elevated: 0, standard: 120 }, sla: { tracked: 121, overdue: 0, accepted: 0, on_track: 121, compliance_percent: 100 }, top_assets: [{ project: 'payments', asset: 'src/app.py', active_findings: 121, priority_sum: 3715, max_priority: 85 }], trend: Array.from({ length: 14 }, (_, index) => ({ date: `2026-01-${String(index + 1).padStart(2, '0')}`, new: index === 0 ? 121 : 0, resolved: 0 })), generated_at: '2026-01-15T00:00:00Z' });
  }
  if (url.pathname === '/intelligence/status') {
    if (req.method === 'GET') return send(res, 200, { sources: state.intelligence });
  }
  if (url.pathname.startsWith('/intelligence/status/')) {
    const source = state.intelligence.find(item => item.source === url.pathname.split('/')[3]);
    if (!source) return send(res, 404, { detail: 'Source not found' });
    Object.assign(source, body, { status: body.enabled ? 'queued' : 'idle' });
    return send(res, 200, { ok: true });
  }
  if (url.pathname === '/intelligence/sync') {
    for (const name of body.sources) state.intelligence.find(item => item.source === name).status = 'queued';
    return send(res, 202, { queued: body.sources });
  }
  if (url.pathname === '/remediation/policies') {
    if (req.method === 'GET') return send(res, 200, { policies: state.policies });
    const existing = state.policies.find(policy => policy.project === body.project);
    if (existing) Object.assign(existing, body); else state.policies.push({ ...body, updated_at: '2026-01-02T00:00:00Z' });
    return send(res, 200, { policy: body, affected_findings: 121 });
  }
  if (url.pathname === '/integrations') {
    if (state.failIntegrations-- > 0) return send(res, 503, { detail: 'Integration service unavailable' });
    return send(res, 200, { slack: { configured: true, description: 'Synthetic integration' }, jira: { configured: true, description: 'Synthetic integration', project_key: 'SEC' } });
  }
  if (url.pathname === '/parsers') {
    const parsers = [
      { name: 'bandit', display_name: 'Bandit', category: 'sast', description: 'Python', file_types: ['json'], auto_detectable: true, verification_status: 'verified', enabled: true },
      { name: 'legacy', display_name: 'Legacy', category: 'sast', description: 'Compatibility adapter', file_types: ['json'], auto_detectable: false, verification_status: 'unverified', enabled: false, unavailable_reason: 'Fixture validation required' },
    ];
    return send(res, 200, { count: parsers.length, categories: ['sast'], parsers, by_category: { sast: parsers } });
  }
  if (url.pathname === '/findings' || url.pathname === '/assets' || url.pathname === '/findings/export.csv') {
    if (url.pathname === '/findings' && state.failFindings-- > 0) return send(res, 503, { detail: 'Findings temporarily unavailable' });
    let rows = url.pathname === '/assets' ? state.assets : state.findings;
    if (user.projects !== null) rows = rows.filter(row => user.projects.includes(row.project));
    const q = url.searchParams.get('q')?.toLowerCase();
    if (q) rows = rows.filter((row) => JSON.stringify(row).toLowerCase().includes(q));
    for (const key of ['severity', 'status', 'project', 'tool', 'assignee']) if (url.searchParams.get(key)) rows = rows.filter((row) => row[key] === url.searchParams.get(key));
    if (url.pathname === '/findings/export.csv') {
      if (state.failExport) return send(res, 422, { detail: 'More than 10000 findings; refine your filters' });
      res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=untrusted.csv' }); return res.end('title,project\r\n' + rows.map(row => `${row.title},${row.project}`).join('\r\n'));
    }
    const offset = Number(url.searchParams.get('offset') || 0), limit = Number(url.searchParams.get('limit') || 100);
    return send(res, 200, { count: rows.length, page_count: rows.slice(offset, offset + limit).length, offset, results: rows.slice(offset, offset + limit) });
  }
  if (url.pathname === '/assets/upsert') {
    const existing = state.assets.find((row) => row.key === body.key && row.project === body.project);
    if (existing) Object.assign(existing, body); else state.assets.unshift({ ...asset(999), ...body });
    return send(res, 200, { ok: true });
  }
  if (url.pathname.startsWith('/findings/')) {
    const record = state.findings.find((row) => row.id === url.pathname.split('/')[2]);
    if (!record) return send(res, 404, { detail: 'Finding not found' });
    if (req.method === 'PATCH') {
      if (state.failPatch-- > 0) return send(res, 503, { detail: 'Temporary save failure' });
      Object.assign(record, body);
      if (body.status === 'verification_pending') record.workflow = { disposition_reason: null, duplicate_of_id: null, verification_requested_at: '2026-01-02T00:00:00Z', verified_at: null, verified_by: null };
      else if (body.status === 'false_positive' || body.status === 'duplicate') record.workflow = { disposition_reason: body.reason, duplicate_of_id: body.duplicate_of_id || null, verification_requested_at: null, verified_at: null, verified_by: null };
      else if (body.status) record.workflow = { disposition_reason: null, duplicate_of_id: null, verification_requested_at: null, verified_at: null, verified_by: null };
      return send(res, 200, { ok: true, finding: { status: record.status, assignee: record.assignee, workflow: record.workflow } });
    }
    if (req.method === 'POST' && url.pathname.endsWith('/comments')) {
      const comment = { id: String(record.comments.length + 1), author: user.username, content: body.content, action_type: 'comment', created_at: '2026-01-02T00:00:00Z' };
      record.comments.unshift(comment); return send(res, 200, { ok: true, comment });
    }
    if (req.method === 'POST' && url.pathname.endsWith('/risk-acceptance')) {
      record.risk_acceptance = { status: 'active', accepted_at: '2026-01-02T00:00:00Z', expires_at: body.expires_at, accepted_by: user.username, reason: body.reason };
      return send(res, 200, { ok: true, expires_at: body.expires_at });
    }
    if (req.method === 'DELETE' && url.pathname.endsWith('/risk-acceptance')) {
      record.risk_acceptance = { status: 'none', accepted_at: null, expires_at: null, accepted_by: null, reason: null };
      res.writeHead(204); return res.end();
    }
    return send(res, 200, record);
  }
  if (url.pathname === '/import/scan') return send(res, 200, { ok: true, imported: 1, new_findings: 1, deduplicated: 0, message: 'Imported fixture successfully' });
  if (url.pathname === '/imports') return send(res, 200, { count: 1, page_count: 1, offset: 0, results: [{ id: 'import-1', parser: 'bandit', filename: 'scan.json', project: 'payments', actor: 'reviewer', status: 'completed', imported: 2, new_findings: 1, deduplicated: 1, error: null, created_at: '2026-01-01T00:00:00Z', completed_at: '2026-01-01T00:00:01Z' }] });
  if (url.pathname === '/notifications') return send(res, 200, { count: 1, page_count: 1, offset: 0, results: [{ id: '00000042-1111-4111-8111-111111111111', finding_id: state.findings[0].id, channel: 'jira', status: state.notificationRetried ? 'pending' : 'needs_review', attempts: 1, last_error: 'Delivery result uncertain', external_id: null, external_url: null, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:01Z', next_attempt_at: null }] });
  if (url.pathname.endsWith('/retry') && url.pathname.startsWith('/notifications/')) {
    if (!body.confirmed_no_issue) return send(res, 409, { detail: 'Operator confirmation required' });
    state.notificationRetried = true; return send(res, 200, { ok: true });
  }
  if (url.pathname === '/risks') return send(res, 200, { count: 0, page_count: 0, offset: 0, results: [] });
  return send(res, 404, { detail: 'Unknown synthetic endpoint' });
});
server.listen(15101, '127.0.0.1');
const children = [
  ['15100', { DASHBOARD_ORIGINS: 'http://127.0.0.1:15100,http://localhost:15100,https://dashboard.secops.invalid' }],
  ['15102', { DASHBOARD_ORIGINS: 'https://dashboard.secops.invalid/path' }],
  ['15103', { BACKEND_URL: 'file:///invalid' }],
].map(([port, overrides]) => spawn(process.execPath, ['.next/standalone/server.js'], {
  stdio: 'inherit', env: { ...process.env, NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1',
    HOSTNAME: '0.0.0.0', PORT: port, BACKEND_URL: 'http://127.0.0.1:15101', ...overrides },
}));
function shutdown() { for (const child of children) child.kill('SIGTERM'); server.close(); }
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, shutdown);
for (const child of children) child.on('exit', (code) => { if (code && code !== 0) { shutdown(); process.exitCode = code; } });
