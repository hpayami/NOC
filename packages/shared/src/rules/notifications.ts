import type { WebhookPayload } from '../entities/operations';

/** Deterministic plain-text e-mail for a condition event. Same facts as the webhook payload. */
export function renderNotificationEmail(p: WebhookPayload): { subject: string; text: string } {
  const c = p.condition;
  const tag =
    p.event === 'resolved' ? 'RESOLVED' : p.event === 'test' ? 'TEST' : c.severity.toUpperCase();
  const subject = `[NOC] ${tag}: ${c.title}`.slice(0, 200);
  const lines = [
    `Event: ${p.event}`,
    `Condition: ${c.id}`,
    `Severity: ${c.severity}`,
    `Count: ${c.count}`,
    '',
    c.detail,
    '',
    c.link ? `Workspace: ${c.link}` : 'Workspace: —',
    `At: ${p.at}`,
    `Platform: ${p.platform.service} ${p.platform.version}`,
    '',
    'This message was generated from platform records; nothing in it is estimated.',
  ];
  return { subject, text: lines.join('\n') };
}
