import { describe, expect, it } from 'vitest';
import {
  CreateRunRequest,
  EXECUTABLE_TECHNIQUES,
  findingForOpenPort,
  validateEngagementTransition,
} from '../src';

describe('engagement lifecycle', () => {
  it('follows draft → pending → approved → active → completed with reasons where it matters', () => {
    expect(validateEngagementTransition('draft', 'pending_approval')).toEqual({
      ok: true,
      requiresReason: false,
    });
    expect(validateEngagementTransition('pending_approval', 'approved')).toMatchObject({
      ok: true,
    });
    expect(validateEngagementTransition('approved', 'active')).toMatchObject({ ok: true });
    expect(validateEngagementTransition('active', 'completed')).toMatchObject({ ok: false });
    expect(
      validateEngagementTransition(
        'active',
        'completed',
        'All objectives covered; report delivered',
      ),
    ).toMatchObject({ ok: true, requiresReason: true });
    expect(validateEngagementTransition('draft', 'active')).toMatchObject({ ok: false });
    expect(validateEngagementTransition('completed', 'active', 'reopen please now')).toMatchObject({
      ok: false,
    });
    expect(validateEngagementTransition('active', 'active')).toMatchObject({ ok: false });
  });
  it('only connect-level techniques are executable in-platform', () => {
    expect(EXECUTABLE_TECHNIQUES).toEqual(['host_discovery', 'service_fingerprint']);
    expect(CreateRunRequest.parse({ technique: 'host_discovery' })).toMatchObject({ dryRun: true });
  });
  it('maps risky open ports to observed-exposure findings and ignores others', () => {
    expect(findingForOpenPort(6379)).toMatchObject({ severity: 'high', cwe: ['CWE-306'] });
    expect(findingForOpenPort(23)?.title).toBe('Exposed Telnet service on tcp/23');
    expect(findingForOpenPort(443)).toBeNull();
  });
});
