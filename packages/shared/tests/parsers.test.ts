import { describe, expect, it } from 'vitest';
import { parseDhcpdLeases, parseIpNeigh } from '../src';

describe('ip neigh parser', () => {
  it('parses reachable entries, drops failed ones without a MAC, classifies ndp', () => {
    const text = `10.20.5.1 dev eth0 lladdr AA:BB:CC:DD:EE:01 REACHABLE
10.20.5.9 dev eth0 lladdr aa:bb:cc:dd:ee:09 STALE
10.20.5.77 dev eth0  FAILED
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router REACHABLE
garbage line
`;
    const r = parseIpNeigh(text, '2026-10-18T12:00:00Z');
    expect(r.map((e) => [e.ip, e.mac, e.source, e.interface])).toEqual([
      ['10.20.5.1', 'aa:bb:cc:dd:ee:01', 'arp', 'eth0'],
      ['10.20.5.9', 'aa:bb:cc:dd:ee:09', 'arp', 'eth0'],
      ['fe80::1', 'aa:bb:cc:dd:ee:01', 'ndp', 'eth0'],
    ]);
  });
});

describe('dhcpd.leases parser', () => {
  const text = `
lease 10.20.5.50 {
  starts 6 2026/10/18 10:00:00;
  ends 6 2026/10/18 22:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:50;
  client-hostname "printer-lobby";
}
lease 10.20.5.51 {
  starts 6 2026/10/18 10:00:00;
  ends 6 2026/10/18 11:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:51;
}
lease 10.20.5.52 {
  starts 6 2026/10/18 10:00:00;
  ends 6 2026/10/18 22:00:00;
  binding state free;
  hardware ethernet aa:bb:cc:dd:ee:52;
}
lease 10.20.5.50 {
  starts 6 2026/10/18 11:30:00;
  ends 6 2026/10/18 23:30:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:5a;
  client-hostname "printer-lobby";
}
`;
  it('keeps only active, unexpired leases and lets later declarations win', () => {
    const r = parseDhcpdLeases(text, new Date('2026-10-18T12:00:00Z'));
    expect(r).toEqual([
      {
        ip: '10.20.5.50',
        mac: 'aa:bb:cc:dd:ee:5a',
        source: 'dhcp',
        hostname: 'printer-lobby',
        observedAt: '2026-10-18T11:30:00.000Z',
        interface: null,
        vlanId: null,
      },
    ]);
  });
});
