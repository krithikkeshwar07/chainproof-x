from __future__ import annotations

import hashlib
import ipaddress
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


RULE_ID = 'shared-entity-window-v1'
RULE_VERSION = 1
WINDOW_SECONDS = 300
MAX_CORRELATION_EVENTS = 1000
MAX_CORRELATION_RESULTS = 5000


class NormalizationError(ValueError):
    pass


@dataclass(frozen=True)
class SourceEvent:
    event: dict[str, str]
    profile: str


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NormalizationError(f'{field} must be a non-empty string')
    return unicodedata.normalize('NFC', value)


def _exact_fields(value: dict[str, Any], required: set[str], optional: set[str] = frozenset()) -> None:
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing or extra:
        raise NormalizationError(
            'source event fields are ambiguous; '
            f'missing={sorted(missing)}, extra={sorted(extra)}'
        )


def normalize_source_event(value: dict[str, Any]) -> SourceEvent:
    """Map explicit synthetic source formats to the fixed cpx-event-v1 record."""
    if 'format' not in value:
        return SourceEvent(value, 'generic')

    profile = value.get('format')
    common = {'format', 'eventId', 'sourceId', 'occurredAt', 'eventType'}
    if profile == 'windows_event_v1':
        _exact_fields(value, common | {'account', 'computer'})
        actor = _required_text(value['account'], 'account')
        target = _required_text(value['computer'], 'computer')
        prefix = 'windows'
    elif profile == 'linux_audit_v1':
        _exact_fields(value, common | {'user', 'host'})
        actor = _required_text(value['user'], 'user')
        target = _required_text(value['host'], 'host')
        prefix = 'linux_audit'
    elif profile == 'network_event_v1':
        _exact_fields(value, common | {'hostname', 'destinationIp'})
        actor = _required_text(value['hostname'], 'hostname')
        raw_ip = _required_text(value['destinationIp'], 'destinationIp')
        try:
            target = ipaddress.ip_address(raw_ip).compressed
        except ValueError as exc:
            raise NormalizationError('destinationIp must be a valid IPv4 or IPv6 address') from exc
        prefix = 'network'
    else:
        raise NormalizationError('format must be windows_event_v1, linux_audit_v1, or network_event_v1')

    event_id = _required_text(value['eventId'], 'eventId')
    source_id = _required_text(value['sourceId'], 'sourceId')
    occurred_at = _required_text(value['occurredAt'], 'occurredAt')
    event_type = _required_text(value['eventType'], 'eventType')
    return SourceEvent({
        'eventId': event_id,
        'sourceId': source_id,
        'occurredAt': occurred_at,
        'eventType': f'{prefix}.{event_type}',
        'actor': actor,
        'target': target,
    }, str(profile))


def entity_keys(event: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (entity type, normalized key, original label) from canonical fields."""
    kind = event.get('eventType', '').split('.', 1)[0]
    if kind not in {'windows', 'linux_audit', 'network'}:
        return []
    fields: list[tuple[str, str]]
    if kind in {'windows', 'linux_audit'}:
        fields = [('user', event['actor']), ('host', event['target'])]
    else:
        fields = [('host', event['actor']), ('ip', event['target'])]

    result: list[tuple[str, str, str]] = []
    for entity_type, label in fields:
        normalized = unicodedata.normalize('NFC', label).strip().casefold()
        if entity_type == 'host':
            normalized = normalized.rstrip('.')
        elif entity_type == 'ip':
            normalized = ipaddress.ip_address(normalized).compressed
        if normalized:
            result.append((entity_type, normalized, label))
    return result


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).timestamp()


def correlate_events(case_id: str, records: list[dict[str, Any]], evidence_by_event: dict[str, str]) -> list[dict[str, Any]]:
    if len(records) > MAX_CORRELATION_EVENTS:
        raise ValueError(f'correlation is limited to {MAX_CORRELATION_EVENTS} events per case')

    normalized: list[dict[str, Any]] = []
    buckets: dict[tuple[str, str], list[int]] = {}
    for record in records:
        event = json.loads(record['normalized_json'])
        event_entities = entity_keys(event)
        index = len(normalized)
        normalized.append({
            'record': record,
            'event': event,
            'epoch': _epoch(event['occurredAt']),
            'entities': event_entities,
        })
        for entity_type, key, _label in event_entities:
            buckets.setdefault((entity_type, key), []).append(index)

    pairs: dict[tuple[int, int], set[tuple[str, str]]] = {}
    for (entity_type, key), indexes in sorted(buckets.items()):
        indexes.sort(key=lambda item: (normalized[item]['epoch'], normalized[item]['event']['sourceId'].encode('utf-8'), normalized[item]['event']['eventId'].encode('utf-8')))
        for offset, left_index in enumerate(indexes):
            left = normalized[left_index]
            for right_index in indexes[offset + 1:]:
                right = normalized[right_index]
                delta = right['epoch'] - left['epoch']
                if delta > WINDOW_SECONDS:
                    break
                if left['event']['sourceId'] == right['event']['sourceId']:
                    continue
                pair = tuple(sorted((left_index, right_index)))
                pairs.setdefault(pair, set()).add((entity_type, key))
                if len(pairs) > MAX_CORRELATION_RESULTS:
                    raise ValueError(f'correlation result exceeds the {MAX_CORRELATION_RESULTS}-result limit')

    results: list[dict[str, Any]] = []
    for (left_index, right_index), shared in sorted(
        pairs.items(),
        key=lambda item: (
            normalized[item[0][0]]['event']['occurredAt'],
            normalized[item[0][1]]['event']['occurredAt'],
            normalized[item[0][0]]['event']['eventId'],
            normalized[item[0][1]]['event']['eventId'],
        ),
    ):
        left, right = normalized[left_index], normalized[right_index]
        left_record, right_record = left['record'], right['record']
        matched_entities = [f'{entity_type}:{key}' for entity_type, key in sorted(shared)]
        identity = json.dumps([
            'ChainProofX-Correlation-v1', case_id, RULE_ID,
            sorted([
                [left['event']['sourceId'], left['event']['eventId']],
                [right['event']['sourceId'], right['event']['eventId']],
            ]),
            matched_entities,
        ], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        correlation_id = hashlib.sha256(identity).hexdigest()
        explanation = (
            f"Events from distinct sources share {', '.join(matched_entities)} "
            f"within {WINDOW_SECONDS} seconds ({abs(right['epoch'] - left['epoch']):g}s apart). "
            'This is a deterministic relationship candidate, not proof that either source is truthful.'
        )
        refs = []
        for item in (left, right):
            event = item['event']
            refs.append({
                'event_id': event['eventId'],
                'source_id': event['sourceId'],
                'evidence_id': evidence_by_event[event['eventId']],
                'occurred_at': event['occurredAt'],
                'event_type': event['eventType'],
                'canonical_sha256': item['record']['canonical_sha256'],
            })
        results.append({
            'id': correlation_id,
            'case_id': case_id,
            'rule_id': RULE_ID,
            'rule_version': RULE_VERSION,
            'window_seconds': WINDOW_SECONDS,
            'matched_entities': matched_entities,
            'explanation': explanation,
            'start_at': min(left['event']['occurredAt'], right['event']['occurredAt']),
            'end_at': max(left['event']['occurredAt'], right['event']['occurredAt']),
            'events': refs,
            'event_record_ids': [left_record['id'], right_record['id']],
        })
    return results
