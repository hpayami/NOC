import type { RuleSource } from '../enums';
import type { BundleEngine } from '../entities/rules';

/** Which bundle engine a sensor kind consumes; null = the sensor runs no registry rules. */
export function bundleEngineFor(sensorKind: string): BundleEngine | null {
  if (sensorKind === 'suricata') return 'suricata';
  if (sensorKind === 'zeek') return 'zeek';
  return null;
}

const ENGINE_SOURCES: Record<BundleEngine, readonly RuleSource[]> = {
  suricata: ['et_open', 'custom', 'vendor'],
  zeek: ['zeek_script'],
};

export interface BundleCandidate {
  id: string;
  source: RuleSource;
  externalId: string;
  revision: number;
  lifecycle: string;
  enabled: boolean;
  sites: readonly string[];
  contentSha256: string;
  content: string | null;
}

/** A rule with no targets goes everywhere; a targeted rule only to sensors at one of its sites. */
export const ruleTargetsSite = (ruleSites: readonly string[], sensorSite: string | null) =>
  ruleSites.length === 0 || (sensorSite !== null && ruleSites.includes(sensorSite));

/**
 * Deterministic bundle membership: deployed, enabled, with content, of a source the engine
 * consumes, targeted at the sensor's site. Sorted so the manifest (and its digest) is stable.
 */
export function selectBundleRules<T extends BundleCandidate>(
  rules: readonly T[],
  sensor: { kind: string; site: string | null },
): T[] {
  const engine = bundleEngineFor(sensor.kind);
  if (!engine) return [];
  const sources = ENGINE_SOURCES[engine];
  return rules
    .filter(
      (r) =>
        r.lifecycle === 'deployed' &&
        r.enabled &&
        r.content !== null &&
        sources.includes(r.source) &&
        ruleTargetsSite(r.sites, sensor.site),
    )
    .sort(
      (a, b) =>
        a.source.localeCompare(b.source) ||
        a.externalId.localeCompare(b.externalId) ||
        a.revision - b.revision,
    );
}

/** Canonical manifest text; the API hashes it (SHA-256) into `bundleSha256`. */
export function bundleManifest(
  rules: ReadonlyArray<
    Pick<BundleCandidate, 'source' | 'externalId' | 'revision' | 'contentSha256'>
  >,
): string {
  return (
    rules.map((r) => `${r.source}:${r.externalId}:${r.revision}:${r.contentSha256}`).join('\n') +
    '\n'
  );
}
