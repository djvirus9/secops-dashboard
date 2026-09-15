// Deterministic v0.6 browser fixtures. No third-party services are contacted.
export function handleV06({ req, res, url, body, user, users, state, send }) {
  const done = (status, value) => { send(res, status, value); return true; };
  if (!state.v06) {
    const finding = state.findings[0];
    state.v06 = {
      members: { [state.teams[0].id]: [users.reviewer.id] }, rules: [], mappings: [], policies: [],
      alerts: [{ id: '00000001-8888-4888-8888-888888888888', project: 'payments', kind: 'sla', resource_id: finding.id, condition: 'overdue', state: 'open', title: 'Overdue remediation: Finding 1', message: 'The remediation deadline has passed.', owner: 'reviewer', team: 'Platform Security', escalation_contact: '#platform-security', first_seen_at: '2026-01-02T00:00:00Z', last_seen_at: '2026-01-03T00:00:00Z', acknowledged_at: null, acknowledged_by: null, resolved_at: null }],
      links: [{ finding_id: finding.id, issue_key: 'SEC-42', url: 'https://jira.invalid/browse/SEC-42', remote_status: 'In Progress', remote_status_category: 'indeterminate', remote_assignee: 'fixture-account', remote_updated_at: '2026-01-03T00:00:00Z', last_synced_at: '2026-01-03T00:00:00Z', next_sync_at: '2099-01-01T00:00:00Z', status: 'idle', operation: 'pull', last_error: null }],
    };
    if (state.legacyAssignee) finding.assignee = 'departed-owner';
  }
  const data = state.v06;
  const scoped = project => user.projects === null || user.projects.includes(project);
  const project = url.searchParams.get('project') || '';
  const eligible = project => Object.values(users).filter(account => account.active && account.role !== 'viewer' && (account.role === 'admin' || account.projects === null || account.projects.includes(project)));
  const page = rows => { const offset = Number(url.searchParams.get('offset') || 0), limit = Number(url.searchParams.get('limit') || 50); return { count: rows.length, offset, results: rows.slice(offset, offset + limit) }; };
  const ownership = finding => {
    const profile = state.projects.find(row => row.name === finding.project);
    return { status: !finding.assignee ? 'unassigned' : eligible(finding.project).some(account => account.username === finding.assignee) ? 'assigned' : 'invalid_assignee', team_id: profile?.team_id || null, team_name: profile?.team_name || null };
  };
  if (url.pathname === '/ownership/assignees') {
    if (!scoped(project)) return done(404, { detail: 'Project not found' });
    if (state.failAssignees-- > 0) return done(503, { detail: 'Eligible accounts temporarily unavailable' });
    return done(200, page(eligible(project)));
  }
  if (url.pathname === '/ownership/my-teams') return done(200, { results: state.teams.filter(team => data.members[team.id]?.includes(user.id) && state.projects.some(row => row.team_id === team.id && scoped(row.name))) });
  if (url.pathname.startsWith('/ownership/teams/')) {
    if (user.role !== 'admin') return done(403, { detail: 'Administrator required' });
    const [, , , teamId, , userId] = url.pathname.split('/');
    const ids = data.members[teamId] ||= [];
    if (req.method === 'GET') return done(200, { results: Object.values(users).filter(account => ids.includes(account.id)) });
    if (req.method === 'DELETE') data.members[teamId] = ids.filter(id => id !== userId);
    else if (!ids.includes(userId)) ids.push(userId);
    return done(200, { ok: true });
  }
  if (url.pathname === '/ownership/rules') {
    if (req.method === 'GET') return done(200, page(state.projects.filter(row => scoped(row.name) && (!project || row.name === project)).map(row => ({ project: row.name, team_id: row.team_id, team_name: row.team_name, enabled: false, default_assignee: null, ready: false, warning: null, ...data.rules.find(rule => rule.project === row.name) }))));
    if (user.role !== 'admin') return done(403, { detail: 'Administrator required' });
    const rule = { project, ...body, ready: body.enabled && Boolean(body.default_assignee), warning: null };
    data.rules = [...data.rules.filter(row => row.project !== project), rule];
    return done(200, { rule });
  }
  if (url.pathname === '/ownership/queue') {
    let rows = state.findings.filter(row => scoped(row.project) && ['open', 'investigating', 'verification_pending'].includes(row.status));
    const teamId = url.searchParams.get('team_id');
    if (url.searchParams.get('view') === 'team') {
      if (teamId && user.role !== 'admin' && !data.members[teamId]?.includes(user.id)) return done(403, { detail: 'Team membership required' });
      const ids = teamId ? [teamId] : Object.keys(data.members).filter(id => data.members[id].includes(user.id));
      rows = rows.filter(row => ids.includes(ownership(row).team_id));
    } else rows = rows.filter(row => ownership(row).status !== 'assigned');
    return done(200, { ...page(rows.map(row => ({ ...row, ownership: ownership(row) }))), overdue: 0 });
  }
  if (url.pathname === '/automation') return done(200, { policies: data.policies.filter(row => scoped(row.project)), slack_configured: true });
  if (url.pathname === '/automation/policies') {
    if (user.role !== 'admin') return done(403, { detail: 'Administrator required' });
    if (state.failAutomationSave-- > 0) return done(503, { detail: 'Operations policy save temporarily unavailable' });
    const policy = { project, ...body, last_evaluated_at: null, next_evaluation_at: null, last_error: null };
    data.policies = [...data.policies.filter(row => row.project !== project), policy];
    return done(200, { policy });
  }
  if (url.pathname === '/automation/evaluate') {
    if (user.role !== 'admin') return done(403, { detail: 'Administrator required' });
    return done(202, { ok: true });
  }
  if (url.pathname === '/automation/alerts') {
    const filter = url.searchParams.get('state') || 'active', kind = url.searchParams.get('kind');
    return done(200, page(data.alerts.filter(row => scoped(row.project) && (!project || row.project === project) && (!kind || row.kind === kind) && (filter === 'all' || (filter === 'active' ? row.state !== 'resolved' : row.state === 'resolved')))));
  }
  if (url.pathname.startsWith('/automation/alerts/')) {
    const alert = data.alerts.find(row => row.id === url.pathname.split('/')[3] && scoped(row.project));
    if (!alert) return done(404, { detail: 'Alert not found' });
    if (user.role === 'viewer') return done(403, { detail: 'Read-only account' });
    Object.assign(alert, { state: 'acknowledged', acknowledged_by: user.username, acknowledged_at: '2026-01-04T00:00:00Z' });
    return done(200, { alert });
  }
  if (url.pathname === '/jira-sync') {
    if (user.role !== 'admin') return done(403, { detail: 'Administrator required' });
    return done(200, { enabled: true, configured: true, interval_minutes: 30, count: data.links.length, results: data.links });
  }
  if (url.pathname.startsWith('/jira-sync/mappings')) {
    if (user.role !== 'admin') return done(403, { detail: 'Administrator required' });
    if (req.method === 'GET') return done(200, { results: data.mappings });
    const userId = url.pathname.split('/')[3], account = Object.values(users).find(row => row.id === userId);
    const mapping = { user_id: userId, username: account.username, ...body };
    data.mappings = [...data.mappings.filter(row => row.user_id !== userId), mapping];
    return done(200, { mapping });
  }
  const jira = /^\/findings\/([^/]+)\/jira(?:\/(pull|push))?$/.exec(url.pathname);
  if (jira) {
    const finding = state.findings.find(row => row.id === jira[1] && scoped(row.project));
    if (!finding) return done(404, { detail: 'Finding not found' });
    const link = data.links.find(row => row.finding_id === finding.id) || null;
    if (req.method === 'GET') return done(200, { configured: true, enabled: true, link, push_preview: { local_status: finding.status, local_assignee: finding.assignee, status_target_category: { open: 'new', investigating: 'indeterminate', verification_pending: 'done' }[finding.status] || null, assignee_mapped: data.mappings.some(mapping => mapping.username === finding.assignee && mapping.active) }, note: 'Synthetic Jira baseline; no external calls.' });
    if (user.role === 'viewer') return done(403, { detail: 'Read-only account' });
    if (state.failJiraQueue-- > 0) return done(409, { detail: 'Jira changed; refresh and review again' });
    if (!link) return done(409, { detail: 'No linked Jira issue' });
    link.status = 'queued'; link.operation = jira[2] === 'pull' ? 'pull' : `push_${body.field}`;
    return done(202, { ok: true });
  }
  return false;
}
