import { describe, expect, it } from 'vitest';
import { CreateNotificationChannelRequest, renderNotificationEmail } from '../src';

describe('notification e-mail rendering and channel contracts', () => {
  it('renders a deterministic subject and body from the condition', () => {
    const r = renderNotificationEmail({
      event: 'raised',
      condition: {
        id: 'sensors_silent',
        severity: 'critical',
        title: 'Sensors silent',
        detail: '2 sensors silent: a, b',
        count: 2,
        link: '/nids',
      },
      platform: { service: 'noc-api', version: '1.2.3' },
      at: '2026-10-19T08:00:00.000Z',
    });
    expect(r.subject).toBe('[NOC] CRITICAL: Sensors silent');
    expect(r.text).toContain('Condition: sensors_silent');
    expect(r.text).toContain('2 sensors silent: a, b');
    expect(r.text).toContain('Workspace: /nids');
    expect(r.text).toContain('nothing in it is estimated');
    expect(
      renderNotificationEmail({
        event: 'resolved',
        condition: {
          id: 'x',
          severity: 'info',
          title: 'Condition resolved',
          detail: 'gone',
          count: 0,
          link: null,
        },
        platform: { service: 'noc-api', version: 'v' },
        at: '2026-10-19T08:00:00.000Z',
      }).subject,
    ).toBe('[NOC] RESOLVED: Condition resolved');
  });

  it('accepts webhook channels without a kind and e-mail channels with SMTP settings, refusing bad ones', () => {
    expect(
      CreateNotificationChannelRequest.parse({
        name: 'w',
        url: 'https://hooks.example/x',
        secret: 'a'.repeat(16),
      }).kind,
    ).toBe('webhook');
    const e = CreateNotificationChannelRequest.parse({
      kind: 'email',
      name: 'e',
      email: { host: 'mail.example', from: 'noc@example.test', recipients: ['a@example.test'] },
    });
    expect(e.kind).toBe('email');
    if (e.kind === 'email') {
      expect(e.email.port).toBe(587);
      expect(e.email.starttls).toBe(true);
      expect(e.password).toBeNull();
    }
    expect(
      CreateNotificationChannelRequest.safeParse({
        kind: 'email',
        name: 'e',
        email: { host: 'bad host', from: 'noc@example.test', recipients: ['a@example.test'] },
      }).success,
    ).toBe(false);
    expect(
      CreateNotificationChannelRequest.safeParse({
        kind: 'email',
        name: 'e',
        email: { host: 'mail.example', from: 'not-an-address', recipients: ['a@example.test'] },
      }).success,
    ).toBe(false);
    expect(
      CreateNotificationChannelRequest.safeParse({
        kind: 'webhook',
        name: 'w',
        url: 'ftp://x/y',
        secret: 'a'.repeat(16),
      }).success,
    ).toBe(false);
  });
});
