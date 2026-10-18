# NOC reference sensor agent

Runs next to a Suricata engine (host service or sidecar) and keeps it in step with the platform:

| Loop          | What it does                                                                                                         | Honesty rule                                                                                          |
| ------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Enrolment     | Exchanges a one-time enrolment token for the sensor credential (stored `0600`, never logged)                         | Token is used once; a bad token is an error, not a retry storm                                        |
| Heartbeat     | Health from `suricatasc` (`uptime`, `version`, `dump-counters`), running bundle digest, inline capability            | Engine unreachable → `failed`; counters absent → `null`, never zero; `inlineCapable` only with a hook |
| Rule bundle   | `GET /agents/rules-bundle` with `If-None-Match`; writes the managed rules file atomically; `suricatasc reload-rules` | The digest is reported only after a **successful reload**; a failed reload is reported in `detail`    |
| IPS directive | `GET /agents/ips-directive`; applies through an operator hook; `POST /agents/ips-ack`                                | `ips`/`ips_test` without `SENSOR_INLINE_CAPABLE=true` **and** a hook → acknowledged as _not applied_  |
| EVE shipping  | Tails `eve.json` from a checkpoint, posts bounded NDJSON batches                                                     | Checkpoint advances only on `202`; partial lines wait; rotation restarts the new file                 |

No third-party dependencies (standard library only).

## Configuration (environment)

| Variable                 | Default                                     | Meaning                                                                |
| ------------------------ | ------------------------------------------- | ---------------------------------------------------------------------- |
| `NOC_API_URL`            | `http://127.0.0.1:4000`                     | Platform API base URL                                                  |
| `NOC_ENROLMENT_TOKEN`    | —                                           | One-time token from `POST /api/v1/sensors/{id}/enrolment-token`        |
| `NOC_CREDENTIAL_FILE`    | `/var/lib/noc-agent/credential`             | Where the sensor credential is kept after enrolment                    |
| `NOC_STATE_DIR`          | `/var/lib/noc-agent`                        | ETag, running digest, directive version, EVE checkpoint                |
| `SURICATA_RULES_FILE`    | `/var/lib/suricata/rules/noc-managed.rules` | Managed rules file; include it from `suricata.yaml` (`rule-files`)     |
| `SURICATA_SOCKET`        | `/var/run/suricata/suricata-command.socket` | Unix command socket (`unix-command.enabled: yes`)                      |
| `SURICATA_EVE_LOG`       | `/var/log/suricata/eve.json`                | EVE log to ship (empty to disable)                                     |
| `NOC_IPS_APPLY_HOOK`     | —                                           | Operator script that receives the directive JSON on stdin              |
| `SENSOR_INLINE_CAPABLE`  | `false`                                     | Declare the host inline-capable (NFQUEUE/AF_PACKET copy mode in place) |
| `NOC_HEARTBEAT_INTERVAL` | `30` s                                      | Also `NOC_BUNDLE_INTERVAL` (60) and `NOC_DIRECTIVE_INTERVAL` (15)      |
| `NOC_CA_FILE`            | —                                           | CA bundle for a private TLS authority                                  |

Run: `noc-sensor-agent` (loop) or `noc-sensor-agent --once` (one cycle, exit 1 if anything failed).

## Detection validation (offline replay)

Set `NOC_VALIDATION_SAMPLES_DIR` to a directory of curated sample captures. Every
`NOC_VALIDATION_INTERVAL` seconds (default 30) the agent fetches queued validations; for each it
runs `suricata -r <sample> -S <managed rules> -l <tmp> -k none --runmode single`, reads the
signature ids that fired from the offline `eve.json` (or `fast.log`) and reports them with the
engine version and the bundle digest it is running. A sample name must be a bare file name inside
the directory; path components, hidden files and missing files are reported as unavailable. If the
agent is not running the bundle the platform expected it says so instead of replaying. Nothing is
sent on any interface and the sample never leaves the host.

## The IPS hook contract

The agent does **not** change Suricata's capture mode itself. For inline prevention the operator
provides a script; the agent calls it with the directive JSON on stdin for `ips`/`ips_test` and,
when the host is declared capable, again on return to `ids`. Exit 0 = applied (stdout is the ack
detail), non-zero = not applied (stderr is reported). The platform's continuation gate returns the
sensor to detect-only on any failed or missing acknowledgement.
