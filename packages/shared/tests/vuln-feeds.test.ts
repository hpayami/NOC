import { describe, expect, it } from 'vitest';
import { assessAssetRisk, parseVulnerabilityFeed } from '../src';

const NVD = JSON.stringify({
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-0001',
        published: '2024-01-02T10:00:00.000',
        lastModified: '2024-02-01T00:00:00.000',
        descriptions: [
          { lang: 'es', value: 'desc es' },
          { lang: 'en', value: 'PostgreSQL authentication bypass' },
        ],
        metrics: {
          cvssMetricV31: [
            {
              type: 'Secondary',
              cvssData: { version: '3.1', baseScore: 7.5, vectorString: 'CVSS:3.1/secondary' },
            },
            {
              type: 'Primary',
              cvssData: {
                version: '3.1',
                baseScore: 9.8,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              },
            },
          ],
        },
        weaknesses: [
          {
            description: [
              { lang: 'en', value: 'CWE-287' },
              { lang: 'en', value: 'NVD-CWE-noinfo' },
            ],
          },
        ],
      },
    },
    { cve: { id: 'not-a-cve' } },
    { cve: { id: 'CVE-2024-0002', descriptions: [{ lang: 'en', value: 'no metrics' }] } },
  ],
});
const KEV = JSON.stringify({
  vulnerabilities: [
    {
      cveID: 'CVE-2024-0001',
      vulnerabilityName: 'PostgreSQL Auth Bypass',
      shortDescription: 'exploited in the wild',
      dateAdded: '2024-03-01',
      dueDate: '2024-03-22',
    },
    { cveID: 'bogus' },
  ],
});

describe('vulnerability feed parsers', () => {
  it('parses NVD 2.0 with the primary CVSS metric, English description and CWE ids; malformed entries become errors', () => {
    const r = parseVulnerabilityFeed('nvd_2', NVD);
    expect(r.errors).toEqual(['nvd_2[1]: missing or malformed cve.id']);
    expect(r.records.map((x) => x.cveId)).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
    expect(r.records[0]).toMatchObject({
      summary: 'PostgreSQL authentication bypass',
      cvssBaseScore: 9.8,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssVersion: '3.1',
      cwe: ['CWE-287'],
      publishedAt: '2024-01-02T10:00:00.000Z',
      knownExploited: null,
    });
    expect(r.records[1]).toMatchObject({ cvssBaseScore: null, cvssVector: null, cwe: [] });
  });

  it('parses CISA KEV as exploited-in-the-wild without inventing a CVSS score', () => {
    const r = parseVulnerabilityFeed('cisa_kev', KEV);
    expect(r.errors).toEqual(['cisa_kev[1]: missing or malformed cveID']);
    expect(r.records).toHaveLength(1);
    expect(r.records[0]).toMatchObject({
      cveId: 'CVE-2024-0001',
      knownExploited: true,
      kevAddedAt: '2024-03-01T00:00:00.000Z',
      kevDueAt: '2024-03-22T00:00:00.000Z',
      cvssBaseScore: null,
      summary: 'PostgreSQL Auth Bypass: exploited in the wild',
    });
  });

  it('parses the native format, rejects non-JSON and non-arrays, and lets the last duplicate win', () => {
    expect(parseVulnerabilityFeed('noc', '{not json').errors[0]).toMatch(/invalid JSON/);
    expect(parseVulnerabilityFeed('noc', '{"a":1}').errors).toEqual([
      'noc: document must be a JSON array',
    ]);
    expect(parseVulnerabilityFeed('nvd_2', '[]').errors[0]).toMatch(/no `vulnerabilities` array/);
    const r = parseVulnerabilityFeed(
      'noc',
      JSON.stringify([
        { cveId: 'CVE-2020-0001', summary: 'first', cvssBaseScore: 4 },
        {
          cveId: 'CVE-2020-0001',
          summary: 'second',
          cvssBaseScore: 11,
          cwe: ['CWE-79', 'bad'],
          knownExploited: true,
        },
      ]),
    );
    expect(r.records).toHaveLength(1);
    expect(r.records[0]).toMatchObject({
      summary: 'second',
      cvssBaseScore: null,
      cwe: ['CWE-79'],
      knownExploited: true,
    });
  });

  it('raises asset risk for known-exploited and CVSS ≥ 9 findings and says why', () => {
    const base = {
      monitoringCoverage: 'monitored',
      assuranceState: 'no_threat_detected',
      openAlerts: [],
      exposures: [],
      criticality: 'unclassified',
    };
    const plain = assessAssetRisk({
      ...base,
      openFindings: [{ severity: 'high', validated: true }],
    });
    const kev = assessAssetRisk({
      ...base,
      openFindings: [
        { severity: 'high', validated: true, knownExploited: true, cvssBaseScore: 9.8 },
      ],
    });
    expect(kev.score).toBeGreaterThan(plain.score + 25);
    expect(kev.basis.join(' ')).toMatch(/exploitation observed in the wild/);
    expect(kev.basis.join(' ')).toMatch(/CVSS base score of 9.0 or higher/);
  });
});
