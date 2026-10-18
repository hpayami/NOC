import ipaddr from 'ipaddr.js';
import type { AssessmentTechnique } from '../enums';
import type { AuthorizedTargetScope } from '../entities/governance';

export type ScopeDecision = { allowed: true } | { allowed: false; reasons: string[] };

/** Ranges ipaddr.js labels as not publicly routable. Everything else is treated as public. */
const NON_PUBLIC_RANGES = new Set([
  'private',
  'loopback',
  'linkLocal',
  'uniqueLocal',
  'carrierGradeNat',
  'unspecified',
]);

function parse(ip: string): ipaddr.IPv4 | ipaddr.IPv6 | null {
  if (!ipaddr.isValid(ip)) return null;
  let addr = ipaddr.parse(ip);
  if (addr.kind() === 'ipv6' && (addr as ipaddr.IPv6).isIPv4MappedAddress()) {
    addr = (addr as ipaddr.IPv6).toIPv4Address();
  }
  return addr;
}

export function isPubliclyRoutable(ip: string): boolean {
  const a = parse(ip);
  if (!a) return true; // fail closed: unparseable == treat as public
  return !NON_PUBLIC_RANGES.has(a.range());
}

function inCidr(addr: ipaddr.IPv4 | ipaddr.IPv6, cidr: string): boolean {
  if (!ipaddr.isValidCIDR(cidr)) return false;
  const [net, bits] = ipaddr.parseCIDR(cidr);
  if (net.kind() !== addr.kind()) return false;
  return (addr as ipaddr.IPv4).match([net as ipaddr.IPv4, bits]);
}

/**
 * Pure, deny-by-default scope check. This function is the single source of truth and MUST be
 * invoked inside the execution service for every outbound action — UI checks are advisory only.
 * Exclusions always win over inclusions.
 */
export function evaluateTarget(input: {
  scope: AuthorizedTargetScope;
  target: string;
  technique: AssessmentTechnique;
  now: Date;
}): ScopeDecision {
  const { scope, target, technique, now } = input;
  const reasons: string[] = [];
  const addr = parse(target);
  if (!addr)
    return {
      allowed: false,
      reasons: ['target is not a valid IP address (resolve hostnames first)'],
    };

  const start = Date.parse(scope.windowStart);
  const end = Date.parse(scope.windowEnd);
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start)
    reasons.push('authorization window is invalid');
  else if (now.getTime() < start) reasons.push('authorization window has not started');
  else if (now.getTime() >= end) reasons.push('authorization has expired');

  if (!scope.allowedTechniques.includes(technique))
    reasons.push(`technique "${technique}" is not authorized`);

  const normalized = addr.toString();
  const excluded =
    scope.excludeAddresses.some((x) => parse(x)?.toString() === normalized) ||
    scope.excludeCidrs.some((c) => inCidr(addr, c));
  if (excluded) reasons.push('target is explicitly excluded');

  const included =
    scope.includeAddresses.some((x) => parse(x)?.toString() === normalized) ||
    scope.includeCidrs.some((c) => inCidr(addr, c));
  if (!included) reasons.push('target is not within the authorized scope');

  if (isPubliclyRoutable(normalized) && !scope.allowPublicAddresses) {
    reasons.push('public address refused: scope does not explicitly allow public targets');
  }

  return reasons.length === 0 ? { allowed: true } : { allowed: false, reasons };
}
