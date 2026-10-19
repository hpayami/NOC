import net from 'node:net';
import tls from 'node:tls';
import { randomBytes } from 'node:crypto';

export interface MailOptions {
  host: string;
  port: number;
  starttls: boolean;
  username: string | null;
  password: string | null;
  from: string;
  to: readonly string[];
  subject: string;
  text: string;
  timeoutMs?: number;
  /** Test hook: skip TLS entirely (plain socket, no STARTTLS). Never set in production code paths. */
  insecurePlain?: boolean;
}

export interface MailResult {
  ok: boolean;
  /** Last SMTP reply line, e.g. `250 2.0.0 Ok: queued as …` or the rejection. */
  response: string | null;
  error: string | null;
}

const CRLF = '\r\n';

/** RFC 5322 header-safe value: no CR/LF, ASCII only (non-ASCII subject is encoded). */
const headerValue = (v: string) =>
  /^[\x20-\x7e]*$/.test(v)
    ? v.replace(/[\r\n]+/g, ' ')
    : `=?UTF-8?B?${Buffer.from(v, 'utf8').toString('base64')}?=`;

/** Builds the RFC 5322 message; base64 body keeps any UTF-8 text and line length safe. */
export function encodeMessage(
  opts: Pick<MailOptions, 'from' | 'to' | 'subject' | 'text'>,
  now = new Date(),
): string {
  const id = `<${randomBytes(12).toString('hex')}@noc-api>`;
  const body = Buffer.from(opts.text, 'utf8')
    .toString('base64')
    .replace(/(.{76})/g, `$1${CRLF}`);
  return [
    `Date: ${now.toUTCString()}`,
    `From: ${headerValue(opts.from)}`,
    `To: ${opts.to.map(headerValue).join(', ')}`,
    `Subject: ${headerValue(opts.subject)}`,
    `Message-ID: ${id}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    'X-Mailer: noc-api/notifications',
    '',
    body,
  ].join(CRLF);
}

class SmtpSession {
  private socket: net.Socket | tls.TLSSocket;
  private buffer = '';
  private waiters: Array<{ resolve: (lines: string[]) => void; reject: (e: Error) => void }> = [];
  private closed: Error | null = null;

  constructor(socket: net.Socket | tls.TLSSocket) {
    this.socket = socket;
    this.attach();
  }

  private attach() {
    this.socket.removeAllListeners('data');
    this.socket.on('data', (chunk: Buffer) => {
      this.buffer += chunk.toString('utf8');
      this.drain();
    });
    this.socket.once('error', (e: Error) => this.fail(e));
    this.socket.once('close', () => this.fail(new Error('connection closed by server')));
  }

  private fail(e: Error) {
    if (this.closed) return;
    this.closed = e;
    for (const w of this.waiters.splice(0)) w.reject(e);
  }

  /** A reply is complete when a line has a space after the 3-digit code (`250 ` vs `250-`). */
  private drain() {
    while (this.waiters.length) {
      const idx = this.buffer.indexOf(CRLF);
      if (idx < 0) return;
      const lines = this.buffer.split(CRLF);
      const end = lines.findIndex((l) => /^\d{3}(\s|$)/.test(l));
      if (end < 0) return;
      const reply = lines.slice(0, end + 1);
      this.buffer = lines.slice(end + 1).join(CRLF);
      this.waiters.shift()!.resolve(reply);
    }
  }

  read(): Promise<string[]> {
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.drain();
    });
  }

  async command(line: string | null, expect: number[]): Promise<string[]> {
    if (line !== null) this.socket.write(line + CRLF);
    const reply = await this.read();
    const code = Number(reply[reply.length - 1]!.slice(0, 3));
    if (!expect.includes(code)) throw new SmtpError(reply[reply.length - 1]!, line);
    return reply;
  }

  upgrade(host: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const secure = tls.connect({ socket: this.socket, servername: host }, () => {
        if (!secure.authorized) return reject(new Error(`TLS: ${secure.authorizationError}`));
        this.socket = secure;
        this.buffer = '';
        this.attach();
        resolve();
      });
      secure.once('error', reject);
    });
  }

  end() {
    this.socket.end();
  }
  destroy() {
    this.socket.destroy();
  }
}

export class SmtpError extends Error {
  constructor(
    public readonly reply: string,
    public readonly command: string | null,
  ) {
    super(reply);
  }
}

/**
 * Minimal SMTP submission client (RFC 5321): EHLO, STARTTLS when offered (or implicit TLS on
 * 465), AUTH PLAIN/LOGIN when credentials exist, one message. Certificate validation is never
 * relaxed; credentials are never sent on a plain connection unless `insecurePlain` (tests only).
 */
export async function sendMail(opts: MailOptions): Promise<MailResult> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const implicitTls = opts.port === 465 && !opts.insecurePlain;
  let session: SmtpSession | null = null;
  const timer = setTimeout(() => session?.destroy(), timeoutMs);
  try {
    const raw: net.Socket | tls.TLSSocket = await new Promise((resolve, reject) => {
      const s = implicitTls
        ? tls.connect({ host: opts.host, port: opts.port, servername: opts.host }, () => resolve(s))
        : net.connect({ host: opts.host, port: opts.port }, () => resolve(s));
      s.setTimeout(timeoutMs, () => s.destroy(new Error('SMTP timeout')));
      s.once('error', reject);
    });
    if (implicitTls && !(raw as tls.TLSSocket).authorized)
      throw new Error(`TLS: ${(raw as tls.TLSSocket).authorizationError}`);
    session = new SmtpSession(raw);
    await session.command(null, [220]);
    let ehlo = await session.command('EHLO noc-api', [250]);
    const offers = (cap: string) => ehlo.some((l) => l.slice(4).toUpperCase().startsWith(cap));
    let secure = implicitTls;
    if (!secure && !opts.insecurePlain) {
      if (!offers('STARTTLS')) {
        if (opts.starttls) throw new Error('server does not offer STARTTLS');
      } else {
        await session.command('STARTTLS', [220]);
        await session.upgrade(opts.host);
        ehlo = await session.command('EHLO noc-api', [250]);
        secure = true;
      }
    }
    if (opts.username && opts.password !== null) {
      if (!secure && !opts.insecurePlain)
        throw new Error('refusing to send credentials without TLS');
      const auth = ehlo.find((l) => l.slice(4).toUpperCase().startsWith('AUTH')) ?? '';
      if (/\bPLAIN\b/i.test(auth) || !/\bLOGIN\b/i.test(auth)) {
        const token = Buffer.from(`\0${opts.username}\0${opts.password}`, 'utf8').toString(
          'base64',
        );
        await session.command(`AUTH PLAIN ${token}`, [235]);
      } else {
        await session.command('AUTH LOGIN', [334]);
        await session.command(Buffer.from(opts.username, 'utf8').toString('base64'), [334]);
        await session.command(Buffer.from(opts.password, 'utf8').toString('base64'), [235]);
      }
    }
    await session.command(`MAIL FROM:<${opts.from}>`, [250]);
    for (const rcpt of opts.to) await session.command(`RCPT TO:<${rcpt}>`, [250, 251]);
    await session.command('DATA', [354]);
    const message = encodeMessage(opts).replace(/\r\n\./g, '\r\n..');
    const [last] = await session.command(`${message}${CRLF}.`, [250]);
    try {
      await session.command('QUIT', [221]);
    } catch {
      /* some servers close before replying; the message was accepted */
    }
    session.end();
    return { ok: true, response: last ?? null, error: null };
  } catch (err) {
    session?.destroy();
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      response: err instanceof SmtpError ? err.reply : null,
      error: msg.slice(0, 512),
    };
  } finally {
    clearTimeout(timer);
  }
}
