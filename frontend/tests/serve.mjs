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
  status: 'open', assignee: null, risk_score: 70, occurrences: 1, description: 'Synthetic regression evidence',
  recommendation: 'Synthetic regression recommendation', cwe_id: 79, cve_id: null, cvss_score: 7.1,
  component: 'fixture-package', component_version: '1.0', file_path: 'src/app.py', line_number: index,
  references: ['javascript:alert(1)', 'https://security.invalid/advisory'], tags: ['fixture'],
  first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-02T00:00:00Z', signal_id: 'fixture', comments: [],
});
const asset = (index) => ({ id: String(index), project: 'payments', key: `asset-${index}.invalid`, name: `Asset ${index}`, owner: 'security', environment: 'prod', criticality: 'medium', exposure: 'internal', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' });
let state;
function reset() { sessions = new Map([['regression-session', users.reviewer]]); savedViews = []; nextView = 1; state = { findings: Array.from({ length: 121 }, (_, index) => finding(index + 1)), assets: Array.from({ length: 121 }, (_, index) => asset(index + 1)), requests: [], failPatch: 0, failIntegrations: 0, failSummary: 0, failFindings: 0 }; }
reset();
const send = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:15101');
  let content = ''; for await (const chunk of req) content += chunk;
  let body; try { body = content ? JSON.parse(content) : {}; } catch { return send(res, 400, { detail: 'Invalid JSON' }); }
  if (url.pathname === '/__test/reset') { reset(); Object.assign(state, body); return send(res, 200, { ok: true }); }
  if (url.pathname === '/__test/state') return send(res, 200, state);
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
  if (user.role !== 'admin' && ['/users', '/integrations', '/integrations/slack/test', '/notifications'].some(path => url.pathname === path || (path === '/users' && url.pathname.startsWith('/users/')))) return send(res, 403, { detail: 'Administrator required' });
  if (user.role === 'viewer' && req.method !== 'GET' && !url.pathname.startsWith('/saved-views')) return send(res, 403, { detail: 'Read-only account' });
  state.requests.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), method: req.method, body, actor: user.username, hasAuthorization: Boolean(req.headers.authorization), hasApiKey: Boolean(req.headers['x-api-key']), hasSpoofedUser: Boolean(req.headers['x-secops-user']) });
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
    return send(res, 200, { total_findings: 121, active_findings: 121, resolved_findings: 0, critical_findings: 1, assets: 121, active_by_severity: { high: 120 } });
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
      Object.assign(record, body); return send(res, 200, { ok: true, finding: { status: record.status, assignee: record.assignee } });
    }
    if (req.method === 'POST' && url.pathname.endsWith('/comments')) {
      const comment = { id: String(record.comments.length + 1), author: user.username, content: body.content, action_type: 'comment', created_at: '2026-01-02T00:00:00Z' };
      record.comments.unshift(comment); return send(res, 200, { ok: true, comment });
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
