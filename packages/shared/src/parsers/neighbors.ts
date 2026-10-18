import type { NeighborEntry } from '../entities/agents';

const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const normMac = (m: string | undefined) => (m && MAC.test(m) ? m.toLowerCase() : null);

/**
 * Parses `ip -4/-6 neigh show` output. Entries in FAILED/INCOMPLETE state carry no MAC and are
 * reported with `mac: null` so the caller can decide whether to keep them.
 */
export function parseIpNeigh(text: string, observedAt: string): NeighborEntry[] {
  const out: NeighborEntry[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const ip = parts[0]!;
    if (!/^[0-9a-f.:]+$/i.test(ip)) continue;
    const dev = parts.indexOf('dev');
    const lladdr = parts.indexOf('lladdr');
    const state = parts[parts.length - 1] ?? '';
    if (/^(FAILED|INCOMPLETE)$/.test(state) && lladdr < 0) continue;
    out.push({
      ip,
      mac: normMac(lladdr >= 0 ? parts[lladdr + 1] : undefined),
      source: ip.includes(':') ? 'ndp' : 'arp',
      hostname: null,
      observedAt,
      interface: dev >= 0 ? (parts[dev + 1] ?? null) : null,
      vlanId: null,
    });
  }
  return out;
}

/**
 * Parses ISC dhcpd `dhcpd.leases`. Only leases whose binding state is `active` and whose end time
 * is after `now` are returned; later declarations for the same address override earlier ones.
 */
export function parseDhcpdLeases(text: string, now: Date): NeighborEntry[] {
  const leases = new Map<string, NeighborEntry>();
  const block = /lease\s+([0-9.]+)\s*\{([^}]*)\}/g;
  for (const m of text.matchAll(block)) {
    const ip = m[1]!;
    const body = m[2]!;
    const state = /binding state\s+(\w+);/.exec(body)?.[1];
    const ends = /ends\s+\d\s+([0-9/]+ [0-9:]+);/.exec(body)?.[1];
    const endsAt = ends ? new Date(ends.replace(/\//g, '-').replace(' ', 'T') + 'Z') : null;
    if (state !== 'active') {
      leases.delete(ip);
      continue;
    }
    if (endsAt && !Number.isNaN(endsAt.getTime()) && endsAt.getTime() <= now.getTime()) {
      leases.delete(ip);
      continue;
    }
    const mac = normMac(/hardware ethernet\s+([0-9a-f:]+);/i.exec(body)?.[1]);
    const hostname = /client-hostname\s+"([^"]{1,255})";/.exec(body)?.[1] ?? null;
    const starts = /starts\s+\d\s+([0-9/]+ [0-9:]+);/.exec(body)?.[1];
    const observedAt = starts
      ? new Date(starts.replace(/\//g, '-').replace(' ', 'T') + 'Z').toISOString()
      : now.toISOString();
    leases.set(ip, {
      ip,
      mac,
      source: 'dhcp',
      hostname,
      observedAt,
      interface: null,
      vlanId: null,
    });
  }
  return [...leases.values()];
}
