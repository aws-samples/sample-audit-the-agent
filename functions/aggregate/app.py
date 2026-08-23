# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Aggregate Lambda — merges pipeline outputs into a unified audit record.

Combines data from three upstream steps:
- Collect: CloudTrail events, tasks, triggers, trigger classification
- Enrich: CUR/Cost Explorer cost data per-space, per-operation
- Trust Posture: Capability level, permission scope, visibility gaps, risk flags

Produces a single JSON payload that the Analyze and Report functions consume.
"""

import json
import logging
import os
from datetime import datetime, timezone

from space_names import resolve_space_name, get_space_tags

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict, context: object) -> dict:
    """Lambda entry point — aggregate all pipeline data into unified audit record.

    Args:
        event: Dict containing outputs from Collect, Enrich, and Trust Posture steps.
        context: Lambda context.

    Returns:
        Unified audit record ready for Bedrock analysis and HTML report generation.
    """
    collect = event.get('collect', {})
    enrich = event.get('enrich', {})
    trust_posture = event.get('compliance', {})

    summary = collect.get('summary', {})
    tasks = collect.get('tasks', [])
    triggers = collect.get('triggers', [])

    # --- Build unified audit record ---
    audit_record = {
        'report_id': f"audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'period': {
            'start': summary.get('period_start', ''),
            'end': summary.get('period_end', ''),
        },

        # Section 1: Activity Summary
        'activity': {
            'total_events': summary.get('total_events', 0),
            'management_events': summary.get('management_events', 0),
            'data_plane_events': summary.get('data_plane_events', 0),
            'write_events': summary.get('write_events', 0),
            'read_events': summary.get('read_events', 0),
            'by_service': summary.get('by_service', {}),
            'by_action': _top_n(summary.get('by_action', {}), 20),
            'by_trigger_type': summary.get('by_trigger_type', {}),
            'agent_spaces_active': summary.get('agent_spaces_active', []),
        },

        # Section 2: Tasks (Investigations + Chats)
        'tasks': {
            'total': len(tasks),
            'investigations': [t for t in tasks if t.get('task_type') == 'INVESTIGATION'],
            'chats': [t for t in tasks if t.get('task_type') == 'CHAT'],
            'by_priority': _group_by(tasks, 'priority'),
            'by_trigger_type': _group_by(tasks, 'trigger_type'),
        },

        # Section 3: Trigger Attribution (Who authorized it?)
        'triggers': {
            'total': len(triggers),
            'details': triggers,
            'by_type': summary.get('by_trigger_type', {}),
        },

        # Section 4: Cost (What did it cost?)
        'cost': enrich,

        # Section 5: Trust Posture (Should I be concerned?)
        'trust_posture': trust_posture,

        # Section 6: Data Quality
        'data_quality': {
            'events_truncated': collect.get('truncated', False),
            'total_events_collected': summary.get('total_events', 0),
            'vended_logs': collect.get('vended_logs', {}),
            'cost_source': next(iter(enrich.values()), {}).get('source', 'unavailable') if enrich else 'unavailable',
        },
    }

    # --- Enrich with Agent Space friendly names ---
    _resolve_space_names(audit_record)

    logger.info(
        "Aggregated audit record: %s (%d events, %d tasks, %d triggers, cost_source=%s)",
        audit_record['report_id'],
        audit_record['activity']['total_events'],
        audit_record['tasks']['total'],
        audit_record['triggers']['total'],
        audit_record['data_quality']['cost_source'],
    )

    return audit_record


def _top_n(counts: dict, n: int) -> dict:
    """Return top N items from a count dict, sorted descending.

    Args:
        counts: Dict mapping keys to integer counts.
        n: Max items to return.

    Returns:
        Dict with top N items.
    """
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n])


def _group_by(items: list, field: str) -> dict:
    """Group items by a field value and count.

    Args:
        items: List of dicts.
        field: Key to group by.

    Returns:
        Dict mapping field values to counts.
    """
    groups: dict = {}
    for item in items:
        value = item.get(field, 'UNKNOWN') or 'UNKNOWN'
        groups[value] = groups.get(value, 0) + 1
    return groups


def _resolve_space_names(audit_record: dict) -> None:
    """Replace Agent Space UUIDs with human-readable names throughout the record.

    Mutates audit_record in place.

    Args:
        audit_record: The unified audit record to enrich.
    """
    # Resolve in activity section
    spaces = audit_record.get('activity', {}).get('agent_spaces_active', [])
    if spaces:
        audit_record['activity']['agent_spaces_named'] = {
            uuid: resolve_space_name(uuid) for uuid in spaces
        }

    # Resolve in cost section. The cost record is keyed per agent
    # (cost[agent_name]['by_space']), so walk each agent's nested breakdown and
    # attach a name-keyed copy alongside the raw UUID-keyed one. Any legacy
    # top-level cost['by_space'] shape is handled too for backward compatibility.
    cost = audit_record.get('cost', {})

    def _name_by_space(by_space: dict) -> dict:
        named = {}
        for uuid, data in by_space.items():
            name = resolve_space_name(uuid)
            named[name] = dict(data)
            named[name]['uuid'] = uuid
            # Attach the space's own tags (purpose/grouping) from the API,
            # unless enrich already provided them. Fail-open to {}.
            if 'tags' not in named[name]:
                named[name]['tags'] = get_space_tags(uuid)
        return named

    if isinstance(cost, dict):
        # Per-agent structure: cost[agent_name]['by_space']
        for agent_key, agent_cost in cost.items():
            if isinstance(agent_cost, dict) and agent_cost.get('by_space'):
                agent_cost['by_space_named'] = _name_by_space(agent_cost['by_space'])
        # Legacy flat structure: cost['by_space'] at the top level
        if cost.get('by_space'):
            cost['by_space_named'] = _name_by_space(cost['by_space'])

    # Resolve in tasks
    for task in audit_record.get('tasks', {}).get('investigations', []):
        space_id = task.get('agent_space_id', '')
        if space_id:
            task['agent_space_name'] = resolve_space_name(space_id)
    for task in audit_record.get('tasks', {}).get('chats', []):
        space_id = task.get('agent_space_id', '')
        if space_id:
            task['agent_space_name'] = resolve_space_name(space_id)
