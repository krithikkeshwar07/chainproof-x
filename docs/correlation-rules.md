# ChainProof X synthetic correlation rules

## Source adapters

Evidence upload continues to store the uploaded bytes exactly as received. The separate `event` form value may be either the existing six-field `cpx-event-v1` event or one of these strict synthetic adapter objects. Adapter inputs reject unknown/missing fields rather than guessing mappings:

- `windows_event_v1`: `eventId`, `sourceId`, `occurredAt`, `eventType`, `account`, `computer` map to canonical `eventId`, `sourceId`, `occurredAt`, `windows.<eventType>`, `actor`, `target`.
- `linux_audit_v1`: `eventId`, `sourceId`, `occurredAt`, `eventType`, `user`, `host` map to `eventId`, `sourceId`, `occurredAt`, `linux_audit.<eventType>`, `actor`, `target`.
- `network_event_v1`: `eventId`, `sourceId`, `occurredAt`, `eventType`, `hostname`, `destinationIp` map to `eventId`, `sourceId`, `occurredAt`, `network.<eventType>`, `actor`, `target`. `destinationIp` must parse as IPv4 or IPv6 and is serialized in compressed canonical form.

All adapter output is then checked and serialized by the existing canonical event implementation. The profile prefix is part of the hashed `eventType`, so correlation can derive entity roles from canonical, integrity-hashed fields. The adapter object and any uploaded source bytes remain separate; normalization does not claim the upload bytes are a faithful or complete export of that event.

## Rule `shared-entity-window-v1`

Version 1 uses one fixed, deterministic rule and a 300-second inclusive window:

1. Windows and Linux audit events expose `actor` as a `user` entity and `target` as a `host` entity. Network events expose `actor` as a `host` entity and `target` as an `ip` entity.
2. Entity keys use NFC, trim outer whitespace, and Unicode case-fold. Host keys also remove trailing dots; IPs use `ipaddress` canonical text. Entity types never cross-match.
3. Two records correlate when their typed normalized entity key sets overlap, their `sourceId` values differ, and the absolute event timestamp distance is at most 300 seconds. Generic six-field events do not participate until a source adapter exists.
4. One correlation result is emitted per event pair. All shared typed keys are combined in bytewise-sorted order. The event pair is ordered by the source/event identifiers in its deterministic identity payload.
5. Stable correlation IDs are SHA-256 over compact UTF-8 JSON containing the `ChainProofX-Correlation-v1` marker, case ID, rule ID, sorted `[sourceId,eventId]` pairs, and sorted matched entity keys. Recompute replaces that case's prior derived snapshot atomically and produces the same IDs for the same records. Ingesting another event invalidates the old snapshot so earlier results are not presented as current.

Every result stores the rule ID/version, 300-second window, matched keys, plain-language explanation, event references, canonical event digests, and the corresponding evidence object IDs. Recompute is limited to 1,000 events and 5,000 results per case. Duplicate `eventId` values remain rejected at ingestion; recomputation never deduplicates by silently choosing a record.

## Graph API and interpretation

- `POST /api/v1/cases/{case_id}/correlations/recompute` calculates and stores the current derived correlation snapshot from ingested normalized events.
- `GET /api/v1/cases/{case_id}/correlations` returns the stored rule results and source-event/evidence references.
- `GET /api/v1/cases/{case_id}/trust-graph` returns nodes and evidence-backed or rule-backed edges for cases, explicitly associated organizations, normalized entities, evidence objects, events, and correlation incidents.
- `POST /api/v1/cases/{case_id}/organizations` explicitly associates a case with an organization metadata record. Organizations are never guessed from hostnames, usernames, or logs.

Graph edges identify their relationship, rule (when applicable), explanation, and evidence IDs. An incident node represents a deterministic correlation candidate, not an adjudicated incident. Neither event integrity nor a graph relationship establishes source-log truth, collection completeness, causal linkage, or a common human actor.
