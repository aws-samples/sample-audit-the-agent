# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Agent Space name resolution — maps UUIDs to human-readable names.

Names are resolved automatically from the DevOps Agent API
(devops-agent:ListAgentSpaces), which returns the authoritative space name
inline for each agentSpaceId. No manual UUID→name mapping is required.

Sources (in priority order):
1. DevOps Agent API (ListAgentSpaces) — authoritative, auto-resolved
2. Fallback: truncated UUID (if the API is unavailable or the space is absent)
"""

import logging
import os
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get('REGION', 'us-east-1')

# Lazily-built cache of {agentSpaceId: name} from the API. Populated once per
# Lambda invocation. `None` = not yet fetched; `{}` = fetched (possibly empty).
_API_NAME_MAP = None


def _get_api_space_names() -> dict:
    """Build {agentSpaceId: name} from devops-agent ListAgentSpaces.

    Fail-open: any SDK/permission/availability error returns an empty map so
    callers fall back to the truncated-UUID label. Cached for the invocation.
    """
    global _API_NAME_MAP
    if _API_NAME_MAP is not None:
        return _API_NAME_MAP

    _API_NAME_MAP = {}
    try:
        client = boto3.client('devops-agent', region_name=REGION)
        next_token = None
        while True:
            resp = client.list_agent_spaces(nextToken=next_token) if next_token \
                else client.list_agent_spaces()
            for space in resp.get('agentSpaces', []):
                sid = space.get('agentSpaceId')
                name = space.get('name')
                if sid and name:
                    _API_NAME_MAP[sid] = name
            next_token = resp.get('nextToken')
            if not next_token:
                break
        logger.info("Resolved %d agent-space name(s) from API", len(_API_NAME_MAP))
    except Exception as exc:  # noqa: BLE001 — fail-open by design
        logger.info(
            "devops-agent ListAgentSpaces unavailable (%s); falling back to UUID labels",
            type(exc).__name__,
        )

    return _API_NAME_MAP


def resolve_space_name(uuid: str) -> str:
    """Resolve an Agent Space UUID to a human-readable name.

    Priority 1: authoritative name from the DevOps Agent API.
    Priority 2: truncated UUID fallback.
    """
    api_names = _get_api_space_names()
    if uuid in api_names:
        return api_names[uuid]

    # Prefix match (defensive — handles partial/short UUID keys).
    for key, name in api_names.items():
        if uuid.startswith(key) or key.startswith(uuid):
            return name

    return f"space-{uuid[:8]}"


# Cache of {agentSpaceId: {tag_key: tag_value}} from get_agent_space.
_TAGS_CACHE = {}


def get_space_tags(uuid: str) -> dict:
    """Return the user-defined tags for an Agent Space via get_agent_space.

    Tags express purpose/grouping (e.g. application, environment, on-call team) —
    surfaced as-is so the reader can attribute cost to how they organized their
    spaces. AWS-reserved tags (aws:*) are excluded. Fail-open: returns {} on any
    SDK/permission/availability error. Cached per invocation.
    """
    if uuid in _TAGS_CACHE:
        return _TAGS_CACHE[uuid]

    tags = {}
    try:
        client = boto3.client('devops-agent', region_name=REGION)
        resp = client.get_agent_space(agentSpaceId=uuid)
        space = resp.get('agentSpace', resp)
        raw = space.get('tags', {}) or {}
        tags = {k: v for k, v in raw.items() if not str(k).lower().startswith('aws:')}
    except Exception as exc:  # noqa: BLE001 — fail-open by design
        logger.info(
            "devops-agent GetAgentSpace unavailable for %s (%s); no tags",
            uuid[:8], type(exc).__name__,
        )

    _TAGS_CACHE[uuid] = tags
    return tags


def build_space_map_from_roles(discovered_roles: list) -> dict:
    """Best-effort mapping from IAM role patterns to space identifiers.

    Role names like DevOpsAgentRole-AgentSpace-conx7dx3 contain a suffix
    that maps to a specific space. We can't get the friendly name from this,
    but we can group activity by space suffix.
    """
    space_map = {}
    for role in discovered_roles:
        role_name = role.get('role_name', '')
        if 'AgentSpace' in role_name:
            # Extract suffix: DevOpsAgentRole-AgentSpace-conx7dx3 → conx7dx3
            parts = role_name.split('-')
            if len(parts) >= 3:
                suffix = parts[-1]
                space_map[role.get('role_arn', '')] = f"agent-space-{suffix}"
    return space_map


def enrich_report_with_names(audit_record: dict) -> dict:
    """Replace UUIDs with names throughout the audit record."""
    # Process per_agent_space in cost section
    cost = audit_record.get('cost', {})
    per_space = cost.get('per_agent_space', {})
    if per_space:
        named_spaces = {}
        for uuid, data in per_space.items():
            name = resolve_space_name(uuid)
            named_spaces[name] = data
            named_spaces[name]['uuid'] = uuid
        cost['per_agent_space'] = named_spaces

    return audit_record
