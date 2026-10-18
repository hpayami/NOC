import { describe, expect, it } from 'vitest';
import { PERMISSIONS } from '@noc/shared';
import { LOCALES, MESSAGES, dirOf } from '@/i18n/messages';
import { NAV } from '@/lib/nav';

describe('navigation and i18n', () => {
  it('declares all 19 required workspaces with unique slugs', () => {
    expect(NAV).toHaveLength(19);
    expect(new Set(NAV.map((n) => n.slug)).size).toBe(19);
  });
  it('maps every item to a real permission and translated label in every locale', () => {
    for (const n of NAV) {
      expect(PERMISSIONS).toContain(n.permission);
      for (const l of LOCALES) expect(MESSAGES[l][n.label], `${l}:${n.label}`).toBeTruthy();
    }
  });
  it('marks only delivered workspaces (Phase ≤ 1) as implemented', () => {
    expect(
      NAV.filter((n) => n.implemented)
        .map((n) => n.slug)
        .sort(),
    ).toEqual(['administration', 'assets', 'audit-logs', 'command-center', 'noc', 'topology']);
    for (const n of NAV) if (n.implemented) expect(n.phase).toBeLessThanOrEqual(1);
  });
  it('has identical message keys in fa and en and is Persian-first RTL', () => {
    expect(Object.keys(MESSAGES.en).sort()).toEqual(Object.keys(MESSAGES.fa).sort());
    expect(dirOf('fa')).toBe('rtl');
    expect(dirOf('en')).toBe('ltr');
  });
});
