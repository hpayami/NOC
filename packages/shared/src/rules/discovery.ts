import ipaddr from 'ipaddr.js';
import type { AssessmentTechnique } from '../enums';
import type { AuthorizedTargetScope } from '../entities/governance';
import { isPubliclyRoutable } from './scope';

/** Hard platform limits for a single discovery job. */
export const DISCOVERY_MAX_TARGETS = 4096;
export const DISCOVERY_MAX_CONCURRENCY = 16;
export const DISCOVERY_MAX_RPS = 50;
export const DISCOVERY_MAX_PORTS = 16;
/** Only connect-level, non-intrusive techniques are ever executed by discovery jobs. */
export const DISCOVERY_TECHNIQUES: readonly AssessmentTechnique[] = [
  'host_discovery',
  'service_fingerprint',
];

export interface SegmentPolicy {
  id: string;
  cidr: string | null;
  activeDiscoveryAllowed: boolean;
}

export type DiscoveryScopeValidation =
  { ok: true; targetCount: number } | { ok: false; reasons: string[] };

function parseCidr(cidr: string): [ipaddr.IPv4 | ipaddr.IPv6, number] | null {
  return ipaddr.isValidCIDR(cidr) ? ipaddr.parseCIDR(cidr) : null;
}

/** True when every address of `inner` lies inside `outer`. */
export function cidrWithin(inner: string, outer: string): boolean {
  const a = parseCidr(inner);
  const b = parseCidr(outer);
  if (!a || !b || a[0].kind() !== b[0].kind()) return false;
  return a[1] >= b[1] && (a[0] as ipaddr.IPv4).match([b[0] as ipaddr.IPv4, b[1]]);
}

export function addressWithin(ip: string, cidr: string): boolean {
  const c = parseCidr(cidr);
  if (!c || !ipaddr.isValid(ip)) return false;
  const a = ipaddr.parse(ip);
  if (a.kind() !== c[0].kind()) return false;
  return (a as ipaddr.IPv4).match([c[0] as ipaddr.IPv4, c[1]]);
}

function hostCount(cidr: string): number {
  const c = parseCidr(cidr);
  if (!c) return Number.POSITIVE_INFINITY;
  if (c[0].kind() === 'ipv6') return Number.POSITIVE_INFINITY; // v6 ranges are never expanded
  const bits = 32 - c[1];
  return bits >= 31 ? 2 ** bits : Math.max(1, 2 ** bits - (bits <= 1 ? 0 : 2));
}

/**
 * Policy check for an active-discovery scope. Beyond the generic scope rules this enforces the
 * platform's discovery posture: no public targets ever, every include range must sit inside a
 * segment that explicitly allows active discovery, bounded size and rate, connect-level
 * techniques only. Evaluated at creation *and* again by the worker before any packet is sent.
 */
export function validateDiscoveryScope(
  scope: AuthorizedTargetScope,
  segments: readonly SegmentPolicy[],
): DiscoveryScopeValidation {
  const reasons: string[] = [];
  const allowed = segments.filter((s) => s.activeDiscoveryAllowed && s.cidr);
  if (scope.allowPublicAddresses)
    reasons.push('public targets are never allowed for discovery jobs');
  if (scope.includeCidrs.length + scope.includeAddresses.length === 0)
    reasons.push('scope has no targets');
  for (const t of scope.allowedTechniques)
    if (!DISCOVERY_TECHNIQUES.includes(t))
      reasons.push(`technique "${t}" is not a discovery technique`);
  if (scope.maxConcurrency > DISCOVERY_MAX_CONCURRENCY)
    reasons.push(`maxConcurrency exceeds ${DISCOVERY_MAX_CONCURRENCY}`);
  if (scope.maxRequestsPerSecond > DISCOVERY_MAX_RPS)
    reasons.push(`maxRequestsPerSecond exceeds ${DISCOVERY_MAX_RPS}`);

  let count = 0;
  for (const cidr of scope.includeCidrs) {
    const c = parseCidr(cidr);
    if (!c) {
      reasons.push(`invalid CIDR ${cidr}`);
      continue;
    }
    if (c[0].kind() === 'ipv6') reasons.push(`IPv6 range ${cidr}: list explicit addresses instead`);
    if (isPubliclyRoutable(c[0].toString())) reasons.push(`${cidr} is publicly routable`);
    if (!allowed.some((s) => cidrWithin(cidr, s.cidr!)))
      reasons.push(`${cidr} is not inside a segment that allows active discovery`);
    count += hostCount(cidr);
  }
  for (const ip of scope.includeAddresses) {
    if (isPubliclyRoutable(ip)) reasons.push(`${ip} is publicly routable`);
    if (!allowed.some((s) => addressWithin(ip, s.cidr!)))
      reasons.push(`${ip} is not inside a segment that allows active discovery`);
    count += 1;
  }
  if (count > DISCOVERY_MAX_TARGETS)
    reasons.push(`scope expands to ${count} targets; limit is ${DISCOVERY_MAX_TARGETS}`);
  return reasons.length ? { ok: false, reasons } : { ok: true, targetCount: count };
}

/** Expands IPv4 include ranges (host addresses only) and explicit addresses, minus exclusions. */
export function expandTargets(
  scope: AuthorizedTargetScope,
  limit = DISCOVERY_MAX_TARGETS,
): string[] {
  const out = new Set<string>();
  const excluded = (ip: string) =>
    scope.excludeAddresses.includes(ip) || scope.excludeCidrs.some((c) => addressWithin(ip, c));
  for (const cidr of scope.includeCidrs) {
    const c = parseCidr(cidr);
    if (!c || c[0].kind() !== 'ipv4') continue;
    const bits = 32 - c[1];
    const base = (c[0] as ipaddr.IPv4).toByteArray().reduce((acc, b) => acc * 256 + b, 0);
    const size = 2 ** bits;
    const skipEdges = bits > 1;
    for (let i = skipEdges ? 1 : 0; i < size - (skipEdges ? 1 : 0); i++) {
      if (out.size >= limit) return [...out];
      const n = base + i;
      const ip = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
      if (!excluded(ip)) out.add(ip);
    }
  }
  for (const ip of scope.includeAddresses) {
    if (out.size >= limit) break;
    if (ipaddr.isValid(ip) && !excluded(ip)) out.add(ipaddr.parse(ip).toString());
  }
  return [...out];
}
