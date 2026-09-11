// Migrated disposable SQLite + actual FastAPI/worker with a tests-only GitHub client fixture.
import { mkdtemp, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const databaseDir = await mkdtemp(resolve(tmpdir(), 'secops-browser-integration-'));
const backendRoot = resolve(import.meta.dirname, '../../backend');
const python = process.env.SECOPS_TEST_PYTHON || 'python3';
const apiKey = 'integration-admin-0f2e4a6c8d1b3e5f7a9c';
const env = { ...process.env, DATABASE_URL: `sqlite:///${databaseDir}/integration.db`, API_KEY: apiKey,
  INGEST_API_KEY: 'integration-scanner-9c7b5a3e1f8d6c4b2a0e', ALLOWED_HOSTS: '127.0.0.1,localhost',
  CORS_ORIGINS: 'http://127.0.0.1:15110', DASHBOARD_ORIGINS: 'http://127.0.0.1:15110', SESSION_COOKIE_SECURE: 'false',
  DASHBOARD_USERNAME: 'reviewer', DASHBOARD_PASSWORD: 'Integration-password-9b7f2d1e6c4a', ALLOW_INSECURE_NO_AUTH: 'false', ALLOW_UNVERIFIED_PARSERS: 'false',
  SLACK_WEBHOOK_URL: '', JIRA_BASE_URL: '', JIRA_EMAIL: '', JIRA_API_TOKEN: '', JIRA_PROJECT_KEY: '',
  GITHUB_SYNC_TOKEN: '',
  STORE_RAW_SCAN_DATA: 'false', PYTHONDONTWRITEBYTECODE: '1' };
const children = [];
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await Promise.all(children.map((child) => new Promise((resolveExit) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolveExit();
    child.once('exit', resolveExit); child.kill('SIGTERM');
  })));
  await rm(databaseDir, { recursive: true, force: true });
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { void stop(); });
function launch(args, options) {
  const child = spawn(python, args, { cwd: backendRoot, env, stdio: 'inherit', ...options });
  children.push(child);
  return child;
}
try {
  await new Promise((resolveMigration, reject) => {
    const migration = launch(['-m', 'alembic', 'upgrade', 'head']);
    migration.once('error', reject);
    migration.once('exit', (code) => code === 0 ? resolveMigration() : reject(new Error(`Migration failed (${code})`)));
  });
  const backend = launch(['-m', 'uvicorn', '--app-dir', 'tests', 'browser_app:app', '--host', '127.0.0.1', '--port', '15111', '--log-level', 'warning']);
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (backend.exitCode !== null) throw new Error('Integration backend stopped before becoming ready');
    try { ready = (await fetch('http://127.0.0.1:15111/ready')).ok; } catch { /* Starting up. */ }
    if (ready) break;
    await delay(100);
  }
  if (!ready) throw new Error('Integration backend did not become ready');
  await cp('public', '.next/standalone/public', { recursive: true });
  await cp('.next/static', '.next/standalone/.next/static', { recursive: true });
  const frontend = spawn(process.execPath, ['.next/standalone/server.js'], {
    stdio: 'inherit', env: { ...process.env, GITHUB_SYNC_TOKEN: '', NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1',
      HOSTNAME: '0.0.0.0', PORT: '15110', BACKEND_URL: 'http://127.0.0.1:15111',
      DASHBOARD_ORIGINS: 'http://127.0.0.1:15110' },
  });
  children.push(frontend);
  for (const child of [backend, frontend]) child.once('exit', (code) => {
    if (!stopping) { process.exitCode = code || 1; void stop(); }
  });
} catch (error) {
  console.error(error.message); process.exitCode = 1; await stop();
}
