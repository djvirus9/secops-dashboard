import { cp, access } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const server = resolve(root, '.next/standalone/server.js');
try {
  await access(server);
} catch {
  console.error('Production build is missing. Run npm run build first.');
  process.exit(1);
}
await cp(resolve(root, 'public'), resolve(root, '.next/standalone/public'), { recursive: true });
await cp(resolve(root, '.next/static'), resolve(root, '.next/standalone/.next/static'), { recursive: true });
const child = spawn(process.execPath, [server], {
  cwd: root,
  env: { ...process.env, PORT: process.env.PORT || '5000', HOSTNAME: process.env.HOSTNAME || '0.0.0.0' },
  stdio: 'inherit',
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', (code) => process.exit(code ?? 1));
