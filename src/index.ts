#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { posix } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client, type ConnectConfig, type SFTPWrapper } from 'ssh2';
import { z } from 'zod';

const HOST = process.env.SFTP_HOST ?? process.env.SSH_HOST ?? '';
const PORT = Number(process.env.SFTP_PORT ?? process.env.SSH_PORT ?? '22');
const USERNAME = process.env.SFTP_USERNAME ?? process.env.SSH_USERNAME ?? '';
const PASSWORD = process.env.SFTP_PASSWORD ?? process.env.SSH_PASSWORD;
const PRIVATE_KEY_PATH = process.env.SFTP_PRIVATE_KEY_PATH ?? process.env.SSH_PRIVATE_KEY_PATH;
const PRIVATE_KEY = process.env.SFTP_PRIVATE_KEY ?? process.env.SSH_PRIVATE_KEY;
const PASSPHRASE = process.env.SFTP_PRIVATE_KEY_PASSPHRASE ?? process.env.SSH_PRIVATE_KEY_PASSPHRASE;
const ROOT = posix.resolve('/', process.env.SFTP_ROOT ?? '/');
const CONNECT_TIMEOUT_MS = positiveInteger(process.env.SSH_CONNECT_TIMEOUT_MS, 15_000);
const MAX_READ_BYTES = positiveInteger(process.env.SFTP_MAX_READ_BYTES, 5 * 1024 * 1024);
const MAX_OUTPUT_BYTES = positiveInteger(process.env.SSH_MAX_OUTPUT_BYTES, 1024 * 1024);
const EXPECTED_FINGERPRINT = normalizeFingerprint(process.env.SSH_HOST_FINGERPRINT);

function positiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function normalizeFingerprint(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (/^SHA256:/i.test(trimmed)) {
    return Buffer.from(trimmed.slice(7), 'base64').toString('hex');
  }
  return trimmed.toLowerCase().replaceAll(':', '');
}

function connectionConfig(): ConnectConfig {
  if (!HOST) throw new Error('SFTP_HOST (or SSH_HOST) is required.');
  if (!USERNAME) throw new Error('SFTP_USERNAME (or SSH_USERNAME) is required.');
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error('SFTP_PORT must be between 1 and 65535.');

  const privateKey = PRIVATE_KEY_PATH ? readFileSync(PRIVATE_KEY_PATH) : PRIVATE_KEY?.replaceAll('\\n', '\n');
  if (!privateKey && !PASSWORD) throw new Error('Configure a password or private key for SSH authentication.');

  return {
    host: HOST,
    port: PORT,
    username: USERNAME,
    password: PASSWORD,
    privateKey,
    passphrase: PASSPHRASE,
    readyTimeout: CONNECT_TIMEOUT_MS,
    keepaliveInterval: 10_000,
    ...(EXPECTED_FINGERPRINT ? {
      hostHash: 'sha256',
      hostVerifier: (fingerprint: string) => normalizeFingerprint(fingerprint) === EXPECTED_FINGERPRINT,
    } : {}),
  };
}

function remotePath(input: string): string {
  const relative = input.replaceAll('\\', '/').replace(/^\/+/, '');
  const resolved = posix.resolve(ROOT, relative || '.');
  if (ROOT !== '/' && resolved !== ROOT && !resolved.startsWith(`${ROOT}/`)) {
    throw new Error(`Path escapes configured SFTP_ROOT (${ROOT}).`);
  }
  return resolved;
}

function textResult(value: unknown, isError = false) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text' as const, text }], isError };
}

function errorResult(error: unknown) {
  return textResult(`Error: ${error instanceof Error ? error.message : String(error)}`, true);
}

async function withConnection<T>(operation: (client: Client) => Promise<T>): Promise<T> {
  const client = new Client();
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    client.once('ready', () => {
      client.removeListener('error', onError);
      resolve();
    });
    client.once('error', onError);
    client.connect(connectionConfig());
  });
  try {
    return await operation(client);
  } finally {
    client.end();
  }
}

async function withSftp<T>(operation: (sftp: SFTPWrapper) => Promise<T>): Promise<T> {
  return withConnection(async (client) => {
    const sftp = await new Promise<SFTPWrapper>((resolve, reject) => client.sftp((error, value) => error ? reject(error) : resolve(value)));
    try {
      return await operation(sftp);
    } finally {
      sftp.end();
    }
  });
}

function sftpCall<T>(invoke: (callback: (error: Error | undefined | null, value: T) => void) => void): Promise<T> {
  return new Promise<T>((resolve, reject) => invoke((error, value) => error ? reject(error) : resolve(value)));
}

const server = new McpServer({
  name: 'SFTP and SSH',
  version: '1.0.0',
  title: 'SFTP and SSH',
  description: 'Manage files over SFTP and optionally execute commands over SSH.',
  icons: [{ src: 'https://unpkg.com/@cynosure-mcp/sftp-ssh@1.0.0/icon.png', mimeType: 'image/png' }],
});

server.registerTool('sftp_list', {
  description: 'List files and directories at a remote path.',
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  inputSchema: { path: z.string().default('/') },
}, async ({ path }) => {
  try {
    const entries = await withSftp((sftp) => sftpCall<any[]>((cb) => sftp.readdir(remotePath(path), cb)));
    return textResult(entries.map(({ filename, longname, attrs }) => ({
      name: filename,
      type: longname?.startsWith('d') ? 'directory' : longname?.startsWith('l') ? 'symlink' : 'file',
      size: attrs?.size,
      modified: attrs?.mtime ? new Date(attrs.mtime * 1000).toISOString() : undefined,
      permissions: attrs?.mode !== undefined ? `0${(attrs.mode & 0o777).toString(8)}` : undefined,
    })));
  } catch (error) { return errorResult(error); }
});

server.registerTool('sftp_stat', {
  description: 'Get metadata for a remote file or directory.',
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  inputSchema: { path: z.string().min(1) },
}, async ({ path }) => {
  try {
    const attrs = await withSftp((sftp) => sftpCall<any>((cb) => sftp.stat(remotePath(path), cb)));
    return textResult({ path: remotePath(path), size: attrs.size, uid: attrs.uid, gid: attrs.gid, permissions: `0${(attrs.mode & 0o777).toString(8)}`, accessed: new Date(attrs.atime * 1000).toISOString(), modified: new Date(attrs.mtime * 1000).toISOString() });
  } catch (error) { return errorResult(error); }
});

server.registerTool('sftp_read', {
  description: `Read a remote file as UTF-8 text or base64 (maximum ${MAX_READ_BYTES} bytes).`,
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  inputSchema: { path: z.string().min(1), encoding: z.enum(['utf8', 'base64']).default('utf8') },
}, async ({ path, encoding }) => {
  try {
    const data = await withSftp(async (sftp) => {
      const attrs = await sftpCall<any>((cb) => sftp.stat(remotePath(path), cb));
      if (attrs.size > MAX_READ_BYTES) throw new Error(`File is ${attrs.size} bytes; limit is ${MAX_READ_BYTES} bytes.`);
      return sftpCall<Buffer>((cb) => sftp.readFile(remotePath(path), cb));
    });
    return textResult({ path: remotePath(path), encoding, size: data.length, data: data.toString(encoding) });
  } catch (error) { return errorResult(error); }
});

server.registerTool('sftp_write', {
  description: 'Create or overwrite a remote file from UTF-8 text or base64 data.',
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  inputSchema: { path: z.string().min(1), data: z.string(), encoding: z.enum(['utf8', 'base64']).default('utf8') },
}, async ({ path, data, encoding }) => {
  try {
    const buffer = Buffer.from(data, encoding);
    await withSftp((sftp) => sftpCall<void>((cb) => sftp.writeFile(remotePath(path), buffer, cb)));
    return textResult(`Wrote ${buffer.length} bytes to ${remotePath(path)}.`);
  } catch (error) { return errorResult(error); }
});

server.registerTool('sftp_mkdir', {
  description: 'Create a remote directory.',
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  inputSchema: { path: z.string().min(1) },
}, async ({ path }) => {
  try {
    await withSftp((sftp) => sftpCall<void>((cb) => sftp.mkdir(remotePath(path), cb)));
    return textResult(`Created directory ${remotePath(path)}.`);
  } catch (error) { return errorResult(error); }
});

server.registerTool('sftp_rename', {
  description: 'Rename or move a remote file or directory within the configured root.',
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  inputSchema: { from: z.string().min(1), to: z.string().min(1) },
}, async ({ from, to }) => {
  try {
    await withSftp((sftp) => sftpCall<void>((cb) => sftp.rename(remotePath(from), remotePath(to), cb)));
    return textResult(`Renamed ${remotePath(from)} to ${remotePath(to)}.`);
  } catch (error) { return errorResult(error); }
});

server.registerTool('sftp_delete', {
  description: 'Delete one remote file or one empty directory. This is not recursive.',
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  inputSchema: { path: z.string().min(1), type: z.enum(['file', 'directory']) },
}, async ({ path, type }) => {
  try {
    await withSftp((sftp) => sftpCall<void>((cb) => type === 'directory' ? sftp.rmdir(remotePath(path), cb) : sftp.unlink(remotePath(path), cb)));
    return textResult(`Deleted ${type} ${remotePath(path)}.`);
  } catch (error) { return errorResult(error); }
});

server.registerTool('ssh_exec', {
  description: 'Execute a non-interactive command on the remote server over SSH.',
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  inputSchema: { command: z.string().min(1), timeout_ms: z.number().int().min(100).max(300_000).default(30_000) },
}, async ({ command, timeout_ms }) => {
  try {
    const result = await withConnection((client) => new Promise<{ stdout: string; stderr: string; exitCode: number | null; signal?: string }>((resolve, reject) => {
      client.exec(command, (error, stream) => {
        if (error) return reject(error);
        const stdout: Buffer[] = [];
        const stderr: Buffer[] = [];
        let total = 0;
        const timer = setTimeout(() => {
          stream.close();
          reject(new Error(`Command timed out after ${timeout_ms} ms.`));
        }, timeout_ms);
        const collect = (chunks: Buffer[]) => (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_OUTPUT_BYTES) {
            clearTimeout(timer);
            stream.close();
            reject(new Error(`Command output exceeded ${MAX_OUTPUT_BYTES} bytes.`));
            return;
          }
          chunks.push(Buffer.from(chunk));
        };
        stream.on('data', collect(stdout));
        stream.stderr.on('data', collect(stderr));
        stream.on('close', (code: number | null, signal?: string) => {
          clearTimeout(timer);
          resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), exitCode: code, signal });
        });
        stream.on('error', (streamError: Error) => { clearTimeout(timer); reject(streamError); });
      });
    }));
    return textResult(result, result.exitCode !== 0);
  } catch (error) { return errorResult(error); }
});

async function main() {
  await server.connect(new StdioServerTransport());
  console.error(`SFTP and SSH MCP running on stdio for ${USERNAME || '<unset>'}@${HOST || '<unset>'}:${PORT}, root ${ROOT}`);
}

main().catch((error) => {
  console.error('Failed to start SFTP and SSH MCP:', error);
  process.exit(1);
});
