# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Collect Lambda — queries CloudTrail for AWS DevOps Agent activity.

Data collection strategy (validated against real account data):

Source 1: CloudTrail EventSource=aidevops.amazonaws.com
  - Management plane events: CreateBacklogTask, CreateChat, CreateOneTimeLoginSession,
    ListAssociations, ListWebhooks, UpdateAssociation, UpdateAgentSpace, TagResource,
    AuthenticateAccessToken, ListAgentSpaces, ListServices, SearchServiceAccessibleResource
  - Provides: trigger attribution (userAgent), task lifecycle (taskId, priority, status),
    agent space context, integration inventory

Source 2: CloudTrail by agent role ARN (optional, for data plane)
  - What resources the agent actually accessed during execution
  - Filtered by role names discovered via IAM trust policy scan

Trigger classification is derived from the `userAgent` field:
  - Browser (Chrome/Safari) → human-console
  - aws-sdk + exec-env/AWS_Lambda → lambda-webhook (automated)
  - cloudformation.amazonaws.com → iac-deployment
  - node → mcp-client (Kiro CLI)
  - aidevops.amazonaws.com → agent-internal
  - events.amazonaws.com → eventbridge-rule

Vended logs: Demoted to optional readiness indicator. Currently only emits
TOPOLOGY_CREATION/REFRESH events — no investigation or chat data.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3

from agent_config import (
    get_active_agents,
    get_all_event_sources,
    get_all_trigger_events,
    classify_event_to_agent,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

AGENT_ROLE_ARNS = [
    arn.strip()
    for arn in os.environ.get('AGENT_ROLE_ARNS', '').split(',')
    if arn.strip()
]
REGION = os.environ.get('REGION', 'us-east-1')
VENDED_LOG_GROUP = os.environ.get('VENDED_LOG_GROUP', '')

# Events that represent agent work initiation (loaded from config)
TRIGGER_EVENTS = get_all_trigger_events()

# Configuration and context events are used for categorization (not trigger detection)
# These are informational — loaded dynamically from active agents
_active_agents = get_active_agents()
CONFIG_EVENTS = frozenset().union(*(a.config_events for a in _active_agents))


def classify_trigger(user_agent: str, source_ip: str, invoked_by: str) -> str:
    """Classify who/what initiated the event based on CloudTrail fields.

    Args:
        user_agent: CloudTrail userAgent field.
        source_ip: CloudTrail sourceIPAddress field.
        invoked_by: CloudTrail userIdentity.invokedBy field.

    Returns:
        Human-readable trigger classification string.
    """
    if invoked_by == 'aidevops.amazonaws.com' or source_ip == 'aidevops.amazonaws.com':
        return 'agent-internal'
    if invoked_by == 'cloudformation.amazonaws.com' or 'cloudformation' in user_agent:
        return 'iac-deployment'
    if 'events.amazonaws.com' in (source_ip + user_agent + invoked_by):
        return 'eventbridge-rule'
    if 'exec-env/AWS_Lambda' in user_agent:
        return 'lambda-webhook'
    if 'Mozilla' in user_agent or 'Chrome' in user_agent or 'Safari' in user_agent:
        return 'human-console'
    if user_agent == 'node':
        return 'mcp-client'
    if 'aws-sdk' in user_agent or 'Boto3' in user_agent:
        return 'sdk-programmatic'
    return 'unknown'


def _parse_cloudtrail_event(raw_event: dict) -> dict:
    """Parse a raw CloudTrail event into a structured audit record.

    Args:
        raw_event: Single event from cloudtrail:LookupEvents response.

    Returns:
        Structured dict with normalized fields.
    """
    ct_event = json.loads(raw_event.get('CloudTrailEvent', '{}'))
    event_time = raw_event.get('EventTime', '')

    user_identity = ct_event.get('userIdentity', {})
    session_context = user_identity.get('sessionContext', {})
    session_issuer = session_context.get('sessionIssuer', {})

    user_agent = ct_event.get('userAgent', '')
    source_ip = ct_event.get('sourceIPAddress', '')
    invoked_by = user_identity.get('invokedBy', '')

    # Extract the human-readable principal name
    principal_arn = user_identity.get('arn', '')
    username = raw_event.get('Username', '')

    # For federated users, extract the login from the role session name
    # e.g., "AROAEXAMPLEID-username-Isengard" → "username"
    human_identity = username
    if '-Isengard' in username:
        parts = username.split('-')
        if len(parts) >= 2:
            human_identity = parts[-2]  # extract username from session name

    return {
        'event_time': event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
        'event_name': raw_event.get('EventName', ''),
        'event_source': ct_event.get('eventSource', ''),
        'event_id': ct_event.get('eventID', ''),
        'read_only': ct_event.get('readOnly', False),
        'agent_type': classify_event_to_agent(ct_event.get('eventSource', '')),
        'user_agent': user_agent,
        'source_ip': source_ip,
        'trigger_type': classify_trigger(user_agent, source_ip, invoked_by),
        'principal': {
            'arn': principal_arn,
            'username': username,
            'human_identity': human_identity,
            'account_id': user_identity.get('accountId', ''),
            'type': user_identity.get('type', ''),
            'invoked_by': invoked_by,
            'role_name': session_issuer.get('userName', ''),
            'session_from_console': ct_event.get('sessionCredentialFromConsole', 'false') == 'true',
        },
        'request_parameters': ct_event.get('requestParameters') or {},
        'response_elements': ct_event.get('responseElements') or {},
        'resources': ct_event.get('resources', raw_event.get('Resources', [])),
    }


def _extract_tasks(events: list) -> list:
    """Extract investigation/chat/pentest task records from parsed events.

    Handles both DevOps Agent (CreateBacklogTask, CreateChat) and
    Security Agent (CreatePentest, StartPentestJob) event structures.

    Args:
        events: List of parsed CloudTrail event dicts.

    Returns:
        List of task summary dicts.
    """
    tasks = []

    for event in events:
        event_name = event['event_name']

        if event_name == 'CreateBacklogTask':
            response = event.get('response_elements', {})
            task_data = response.get('task', {})
            tasks.append({
                'task_id': task_data.get('taskId', ''),
                'execution_id': task_data.get('executionId', ''),
                'agent_space_id': task_data.get('agentSpaceId', ''),
                'task_type': task_data.get('taskType', event.get('request_parameters', {}).get('taskType', '')),
                'priority': task_data.get('priority', event.get('request_parameters', {}).get('priority', '')),
                'status': task_data.get('status', ''),
                'agent_type': event.get('agent_type', 'AWS DevOps Agent'),
                'trigger_type': event['trigger_type'],
                'triggered_by': event['principal']['human_identity'],
                'triggered_at': event['event_time'],
                'user_agent': event['user_agent'],
            })

        elif event_name == 'CreateChat':
            response = event.get('response_elements', {})
            agent_space_id = ''
            for resource in event.get('resources', []):
                arn = resource.get('ARN', '')
                if 'agentspace/' in arn:
                    agent_space_id = arn.split('agentspace/')[-1]
                    break

            tasks.append({
                'task_id': '',
                'execution_id': response.get('executionId', ''),
                'agent_space_id': agent_space_id,
                'task_type': 'CHAT',
                'priority': '',
                'status': 'CREATED',
                'agent_type': event.get('agent_type', 'AWS DevOps Agent'),
                'trigger_type': event['trigger_type'],
                'triggered_by': event['principal']['human_identity'],
                'triggered_at': event['event_time'],
                'user_agent': event['user_agent'],
            })

        elif event_name == 'CreatePentest':
            response = event.get('response_elements', {})
            params = event.get('request_parameters', {})
            tasks.append({
                'task_id': response.get('pentestId', ''),
                'execution_id': '',
                'agent_space_id': params.get('agentSpaceId', ''),
                'task_type': 'PENTEST',
                'priority': params.get('priority', 'MEDIUM'),
                'status': response.get('status', 'CREATED'),
                'agent_type': event.get('agent_type', 'AWS Security Agent'),
                'trigger_type': event['trigger_type'],
                'triggered_by': event['principal']['human_identity'],
                'triggered_at': event['event_time'],
                'user_agent': event['user_agent'],
            })

        elif event_name == 'StartPentestJob':
            response = event.get('response_elements', {})
            params = event.get('request_parameters', {})
            tasks.append({
                'task_id': params.get('pentestId', ''),
                'execution_id': response.get('jobId', ''),
                'agent_space_id': '',
                'task_type': 'PENTEST_JOB',
                'priority': '',
                'status': 'STARTED',
                'agent_type': event.get('agent_type', 'AWS Security Agent'),
                'trigger_type': event['trigger_type'],
                'triggered_by': event['principal']['human_identity'],
                'triggered_at': event['event_time'],
                'user_agent': event['user_agent'],
            })

    return tasks


def _extract_triggers(events: list) -> list:
    """Extract trigger attribution records from write events.

    Args:
        events: List of parsed CloudTrail event dicts.

    Returns:
        List of trigger summary dicts for the audit report.
    """
    triggers = []
    for event in events:
        if event['event_name'] in TRIGGER_EVENTS:
            triggers.append({
                'action': event['event_name'],
                'time': event['event_time'],
                'trigger_type': event['trigger_type'],
                'principal': event['principal']['human_identity'],
                'principal_arn': event['principal']['arn'],
                'user_agent_summary': _summarize_user_agent(event['user_agent']),
                'source_ip': event['source_ip'],
                'from_console': event['principal']['session_from_console'],
            })
    return triggers


def _summarize_user_agent(user_agent: str) -> str:
    """Create a short human-readable summary of the userAgent.

    Args:
        user_agent: Raw userAgent string from CloudTrail.

    Returns:
        Short summary (e.g., "Chrome (macOS)", "AWS Lambda (Node.js 24)").
    """
    if 'Chrome' in user_agent:
        return 'Chrome (Console)'
    if 'exec-env/AWS_Lambda' in user_agent:
        # Extract runtime: "exec-env/AWS_Lambda_nodejs24.x"
        if 'nodejs' in user_agent:
            return 'AWS Lambda (Node.js)'
        if 'python' in user_agent:
            return 'AWS Lambda (Python)'
        return 'AWS Lambda'
    if 'cloudformation' in user_agent:
        return 'CloudFormation (CDK/IaC)'
    if user_agent == 'node':
        return 'Kiro CLI (MCP)'
    if 'Boto3' in user_agent:
        return 'Boto3 (Python SDK)'
    if 'aws-sdk' in user_agent:
        return 'AWS SDK'
    if 'aidevops' in user_agent:
        return 'Agent Internal'
    return user_agent[:50] if user_agent else 'unknown'


def _query_management_events(
    cloudtrail_client: object,
    start_time: datetime,
    end_time: datetime,
) -> list:
    """Query CloudTrail for management events across all active agents.

    Queries each configured agent's event source separately and merges results.

    Args:
        cloudtrail_client: Boto3 CloudTrail client.
        start_time: Start of the query window.
        end_time: End of the query window.

    Returns:
        List of raw CloudTrail event dicts from all active agents.
    """
    events = []
    paginator = cloudtrail_client.get_paginator('lookup_events')

    for event_source in get_all_event_sources():
        try:
            for page in paginator.paginate(
                LookupAttributes=[{
                    'AttributeKey': 'EventSource',
                    'AttributeValue': event_source,
                }],
                StartTime=start_time,
                EndTime=end_time,
            ):
                events.extend(page.get('Events', []))
            logger.info("Collected %d events from %s", len(events), event_source)
        except Exception as exc:
            logger.error("CloudTrail query failed for %s: %s", event_source, exc)

    return events


def _query_role_data_plane(
    cloudtrail_client: object,
    role_arns: list,
    start_time: datetime,
    end_time: datetime,
) -> list:
    """Query CloudTrail for resource-level API calls made by agent roles.

    This captures what the agent *accessed* (S3, EC2, RDS, etc.) during execution.
    Separate from management events which capture who *triggered* the agent.

    Args:
        cloudtrail_client: Boto3 CloudTrail client.
        role_arns: List of IAM role ARNs to query.
        start_time: Start of the query window.
        end_time: End of the query window.

    Returns:
        List of raw CloudTrail event dicts.
    """
    events = []
    paginator = cloudtrail_client.get_paginator('lookup_events')

    for role_arn in role_arns:
        role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn.split(':')[-1]
        try:
            for page in paginator.paginate(
                LookupAttributes=[{
                    'AttributeKey': 'Username',
                    'AttributeValue': role_name,
                }],
                StartTime=start_time,
                EndTime=end_time,
            ):
                events.extend(page.get('Events', []))
        except Exception as exc:
            logger.warning("Role data-plane query failed for %s: %s", role_name, exc)

    return events


def _check_vended_logs_readiness() -> dict:
    """Check if vended logs are configured (readiness indicator only).

    Vended logs currently only emit TOPOLOGY_CREATION/REFRESH events.
    This function checks configuration status without heavy queries.

    Returns:
        Dict with readiness status and log group info.
    """
    if VENDED_LOG_GROUP:
        return {
            'configured': True,
            'log_group': VENDED_LOG_GROUP,
            'note': 'Vended logs configured. Currently emits topology events only.',
        }

    # Auto-discover
    logs_client = boto3.client('logs', region_name=REGION)
    prefixes = ['/aws/vendedlogs/aidevops']

    for prefix in prefixes:
        try:
            response = logs_client.describe_log_groups(
                logGroupNamePrefix=prefix, limit=5
            )
            groups = response.get('logGroups', [])
            if groups:
                return {
                    'configured': True,
                    'log_group': groups[0]['logGroupName'],
                    'discovered': True,
                    'note': 'Vended logs auto-discovered. Currently emits topology events only.',
                }
        except Exception:
            continue

    return {
        'configured': False,
        'note': (
            'Vended logs not configured. Enable via DevOps Agent Console → Settings → Logs. '
            'Currently provides topology health events; future: investigation/chat/webhook events.'
        ),
    }


def handler(event: dict, context: object) -> dict:
    """Lambda entry point — collect agent activity from CloudTrail.

    Returns a structured summary with:
    - All management events (parsed and classified)
    - Task lifecycle records (investigations, chats)
    - Trigger attribution (who/what initiated each action)
    - Resource access events (data plane, if role ARNs configured)
    - Vended logs readiness status

    Args:
        event: Lambda event (unused, pipeline passes context from prior steps).
        context: Lambda context.

    Returns:
        Dict with summary, events, tasks, and triggers for downstream steps.
    """
    cloudtrail = boto3.client('cloudtrail', region_name=REGION)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    logger.info(
        "Collecting agent activity: %s to %s",
        start_time.isoformat(),
        end_time.isoformat(),
    )

    # --- Source 1: Management events (trigger attribution) ---
    raw_management = _query_management_events(cloudtrail, start_time, end_time)
    management_events = [_parse_cloudtrail_event(e) for e in raw_management]
    logger.info("Management events collected: %d", len(management_events))

    # --- Source 2: Data plane events (resource access) ---
    raw_data_plane = _query_role_data_plane(
        cloudtrail, AGENT_ROLE_ARNS, start_time, end_time
    )
    data_plane_events = [_parse_cloudtrail_event(e) for e in raw_data_plane]
    logger.info(
        "Data plane events collected: %d (across %d roles)",
        len(data_plane_events),
        len(AGENT_ROLE_ARNS),
    )

    # --- Deduplicate across sources ---
    all_events_raw = []
    seen_ids = set()
    for parsed_event in management_events + data_plane_events:
        event_id = parsed_event['event_id']
        if event_id and event_id not in seen_ids:
            seen_ids.add(event_id)
            all_events_raw.append(parsed_event)

    # --- Filter to mutating events only (CISO-relevant) ---
    # Keep: readOnly=false (mutations) + ListAssociations (MCP detection)
    KEEP_READ_EVENTS = frozenset({'ListAssociations'})
    read_events_skipped = 0
    all_events = []
    for event in all_events_raw:
        if not event['read_only'] or event['event_name'] in KEEP_READ_EVENTS:
            all_events.append(event)
        else:
            read_events_skipped += 1

    logger.info(
        "Event filter: %d total → %d mutating (kept), %d read-only (skipped)",
        len(all_events_raw), len(all_events), read_events_skipped,
    )

    # --- Extract structured audit data ---
    tasks = _extract_tasks(management_events)
    triggers = _extract_triggers(management_events)

    # --- Drop response_elements from events before passing downstream ---
    # (only needed for task_id extraction above, not for enrich/analyze/report)
    for event in all_events:
        event.pop('response_elements', None)

    # --- Service breakdown ---
    services_accessed = {}
    actions_performed = {}
    for parsed_event in all_events:
        service = parsed_event['event_source']
        action = parsed_event['event_name']
        services_accessed[service] = services_accessed.get(service, 0) + 1
        actions_performed[action] = actions_performed.get(action, 0) + 1

    # --- Vended logs readiness ---
    vended_logs_status = _check_vended_logs_readiness()

    # --- Build summary ---
    summary = {
        'period_start': start_time.isoformat(),
        'period_end': end_time.isoformat(),
        'total_events': len(all_events_raw),
        'mutating_events': len(all_events),
        'read_events_skipped': read_events_skipped,
        'management_events': len(management_events),
        'data_plane_events': len(data_plane_events),
        'write_events': sum(1 for e in all_events if not e['read_only']),
        'read_events': sum(1 for e in all_events if e['read_only']),
        'tasks_initiated': len(tasks),
        'triggers_detected': len(triggers),
        'by_service': services_accessed,
        'by_action': actions_performed,
        'by_trigger_type': _count_by_field(triggers, 'trigger_type'),
        'agent_spaces_active': list(set(
            t['agent_space_id'] for t in tasks if t['agent_space_id']
        )),
    }

    logger.info(
        "Collection complete: %d events, %d tasks, %d triggers, spaces=%s",
        summary['total_events'],
        summary['tasks_initiated'],
        summary['triggers_detected'],
        summary['agent_spaces_active'],
    )

    return {
        'summary': summary,
        'tasks': tasks,
        'triggers': triggers,
        'events': all_events[:500],  # Cap payload size for Step Functions
        'truncated': len(all_events) > 500,
        'vended_logs': vended_logs_status,
    }


def _count_by_field(items: list, field: str) -> dict:
    """Count occurrences of each value for a given field.

    Args:
        items: List of dicts.
        field: Key to group by.

    Returns:
        Dict mapping field values to counts.
    """
    counts: dict = {}
    for item in items:
        value = item.get(field, 'unknown')
        counts[value] = counts.get(value, 0) + 1
    return counts
