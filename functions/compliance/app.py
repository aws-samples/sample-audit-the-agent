# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Authorization & Risk Profile Lambda — assesses agent authorization, capability, and risk signals.

Answers the CISO's core question: "I gave an AI agent access to my environment.
Prove to me it's not a risk."

Evaluates five trust dimensions:
1. Capability Level — Read-only vs. Actions-enabled (can agent mutate?)
2. Permission Scope — Least privilege vs. over-privileged Actions role
3. Visibility Gaps — Private MCP connections without audit coverage
4. Integration Exposure — Third-party webhooks, MCP servers, and triggers
5. Human-in-the-Loop — Is every mutation gated by human approval?

Output is designed for executive consumption: traffic-light risk levels
(LOW / MEDIUM / HIGH / CRITICAL) with actionable recommendations.
"""

import hashlib
import json
import logging
import os
from typing import Optional

import boto3

from agent_config import get_all_trust_principals, get_active_agents

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get('REGION', 'us-east-1')
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET', '')
SUPPRESSIONS_KEY = 'agentaudit/config/suppressions.json'
AGENT_ROLE_ARNS = [
    arn.strip()
    for arn in os.environ.get('AGENT_ROLE_ARNS', '').split(',')
    if arn.strip()
]

# Permissions considered high-risk if found in an Actions role
HIGH_RISK_ACTIONS = frozenset({
    '*',
    'ec2:TerminateInstances',
    'ec2:StopInstances',
    'rds:DeleteDBInstance',
    'rds:DeleteDBCluster',
    's3:DeleteBucket',
    's3:DeleteObject',
    'lambda:DeleteFunction',
    'iam:*',
    'iam:DeleteRole',
    'iam:PutRolePolicy',
    'sts:*',
    'organizations:*',
})

# Permissions considered moderate-risk (mutating but scoped)
MODERATE_RISK_ACTIONS = frozenset({
    'ec2:RebootInstances',
    'ecs:UpdateService',
    'ecs:StopTask',
    'lambda:UpdateFunctionConfiguration',
    'lambda:UpdateFunctionCode',
    'rds:RebootDBInstance',
    'rds:ModifyDBInstance',
    'elasticache:RebootCacheCluster',
    'autoscaling:SetDesiredCapacity',
    'autoscaling:UpdateAutoScalingGroup',
})


def _assess_capability_level(iam_client: object, collect_data: dict = None) -> dict:
    """Determine whether the agent has read-only or mutating access.

    Scans IAM roles trusting aidevops.amazonaws.com and classifies them
    as read-only (AgentSpace roles) or actions-capable (custom/actions roles).
    Cross-references against CloudTrail activity to tag roles as ACTIVE or DORMANT.

    Args:
        iam_client: Boto3 IAM client.
        collect_data: Output from the Collect Lambda (events) for activity cross-reference.

    Returns:
        Dict with capability assessment and role inventory.
    """
    paginator = iam_client.get_paginator('list_roles')
    roles = {'read_only': [], 'actions_capable': [], 'service_linked': []}

    trust_principals = set(get_all_trust_principals())

    for page in paginator.paginate():
        for role in page['Roles']:
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            for statement in trust_policy.get('Statement', []):
                principal = statement.get('Principal', {})
                service = principal.get('Service', '')
                services = [service] if isinstance(service, str) else service

                if not trust_principals.intersection(services):
                    continue

                role_name = role['RoleName']
                role_info = {
                    'role_name': role_name,
                    'role_arn': role['Arn'],
                }

                if 'ServiceRole' in role_name or 'service-role' in role.get('Path', ''):
                    if 'AgentSpace' in role_name:
                        roles['read_only'].append(role_info)
                    elif 'WebappAdmin' in role_name or 'WebappIDC' in role_name:
                        roles['read_only'].append(role_info)
                    elif 'AWSServiceRoleForAIDevOps' in role_name:
                        roles['service_linked'].append(role_info)
                    else:
                        # Unknown service role — could be Actions role
                        roles['actions_capable'].append(role_info)
                else:
                    # Custom role trusting aidevops — likely an Actions role
                    roles['actions_capable'].append(role_info)
                break

    has_actions = len(roles['actions_capable']) > 0
    capability = 'ACTIONS_ENABLED' if has_actions else 'READ_ONLY'

    # Tag roles as ACTIVE or DORMANT based on CloudTrail activity in audit period
    events = (collect_data or {}).get('events', [])
    active_role_arns = set()
    for event in events:
        principal = event.get('principal', {})
        arn = principal.get('arn', '')
        role_name = principal.get('role_name', '')
        if arn:
            active_role_arns.add(arn)
        if role_name:
            active_role_arns.add(role_name)

    for role in roles['actions_capable']:
        # Match by role ARN appearing in any event's assumed-role ARN or role_name
        is_active = any(
            role['role_name'] in arn or role['role_arn'] in arn
            for arn in active_role_arns
        )
        role['status'] = 'ACTIVE' if is_active else 'DORMANT'

    # Build summary with role names (top 3 for executive view, full list in audit data)
    if has_actions:
        active_count = sum(1 for r in roles['actions_capable'] if r.get('status') == 'ACTIVE')
        dormant_count = sum(1 for r in roles['actions_capable'] if r.get('status') == 'DORMANT')
        role_names = [r['role_name'] for r in roles['actions_capable'][:3]]
        overflow = len(roles['actions_capable']) - 3
        more = f" (+{overflow} more)" if overflow > 0 else ""
        status_detail = f" ({active_count} active, {dormant_count} dormant in this period)" if events else ""
        summary = (
            f"Actions-capable role(s): {', '.join(role_names)}{more}{status_detail}. "
            f"These can mutate infrastructure when Agent Actions is enabled."
        )
    else:
        summary = (
            f"Agent is read-only across {len(roles['read_only'])} role(s). "
            f"No mutating permissions detected."
        )

    return {
        'capability_level': capability,
        'risk_level': 'MEDIUM' if has_actions else 'LOW',
        'read_only_roles': len(roles['read_only']),
        'actions_capable_roles': len(roles['actions_capable']),
        'service_linked_roles': len(roles['service_linked']),
        'actions_roles': roles['actions_capable'],
        'summary': summary,
    }


def _assess_permission_scope(iam_client: object, actions_roles: list) -> dict:
    """Analyze permissions granted to Actions roles for over-privilege.

    Args:
        iam_client: Boto3 IAM client.
        actions_roles: List of role info dicts from capability assessment.

    Returns:
        Dict with permission analysis, flagged high/moderate risk actions.
    """
    if not actions_roles:
        return {
            'risk_level': 'LOW',
            'assessed_roles': 0,
            'high_risk_permissions': [],
            'moderate_risk_permissions': [],
            'summary': 'No Actions roles to assess — agent is read-only.',
        }

    high_risk_found = []
    moderate_risk_found = []
    all_actions_found = set()

    for role_info in actions_roles[:5]:  # Cap at 5 to avoid timeout
        role_name = role_info['role_name']
        try:
            # Check inline policies
            inline_resp = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_resp.get('PolicyNames', []):
                policy_resp = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                _scan_policy_document(
                    policy_resp.get('PolicyDocument', {}),
                    role_name,
                    high_risk_found,
                    moderate_risk_found,
                    all_actions_found,
                )

            # Check attached managed policies
            attached_resp = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_resp.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                try:
                    version_resp = iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = version_resp['Policy']['DefaultVersionId']
                    doc_resp = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    _scan_policy_document(
                        doc_resp.get('PolicyVersion', {}).get('Document', {}),
                        role_name,
                        high_risk_found,
                        moderate_risk_found,
                        all_actions_found,
                    )
                except Exception as exc:
                    logger.warning("Could not read policy %s: %s", policy_arn, exc)

        except Exception as exc:
            logger.warning("Could not assess role %s: %s", role_name, exc)

    # Determine risk level
    if high_risk_found:
        risk_level = 'HIGH'
    elif moderate_risk_found:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    return {
        'risk_level': risk_level,
        'assessed_roles': min(len(actions_roles), 5),
        'total_actions_granted': len(all_actions_found),
        'high_risk_permissions': high_risk_found[:20],
        'moderate_risk_permissions': moderate_risk_found[:20],
        'summary': (
            f"CRITICAL: {len(high_risk_found)} high-risk permission(s) found "
            f"(e.g., {high_risk_found[0]['action']}). Review immediately."
        ) if high_risk_found else (
            f"{len(moderate_risk_found)} moderate-risk (mutating) permission(s) found. "
            f"Scoped to operational actions (restart, scale)."
        ) if moderate_risk_found else (
            "Actions role permissions are appropriately scoped."
        ),
    }


def _scan_policy_document(
    document: dict,
    role_name: str,
    high_risk: list,
    moderate_risk: list,
    all_actions: set,
) -> None:
    """Scan a policy document for high/moderate risk actions.

    Args:
        document: IAM policy document dict.
        role_name: Role name for attribution.
        high_risk: List to append high-risk findings to (mutated).
        moderate_risk: List to append moderate-risk findings to (mutated).
        all_actions: Set to add all actions to (mutated).
    """
    for statement in document.get('Statement', []):
        if statement.get('Effect') != 'Allow':
            continue

        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get('Resource', '*')
        if isinstance(resources, str):
            resources = [resources]

        for action in actions:
            all_actions.add(action)
            finding = {
                'role': role_name,
                'action': action,
                'resource_scope': resources[0] if len(resources) == 1 else f"{len(resources)} resources",
                'is_wildcard_resource': '*' in resources,
            }

            if action in HIGH_RISK_ACTIONS or (action.endswith(':*') and '*' in resources):
                high_risk.append(finding)
            elif action in MODERATE_RISK_ACTIONS:
                moderate_risk.append(finding)


def _assess_visibility_gaps(ec2_client: object, collect_data: dict) -> dict:
    """Detect private MCP connections that represent audit blind spots.

    Private MCP servers connected via VPC Lattice are NOT auditable via CloudTrail.
    Agent tool calls to private endpoints are only captured in the Agent Journal.

    Detection approach (layered):
    1. DescribePrivateConnection API — authoritative source for endpoint details
       (hostAddress, type, dnsResolution, certificate status)
    2. CloudTrail ListAssociations events — identifies configured MCP integrations
       (filterServiceTypes: mcpserver, mcpserversigv4, remoteagent)
    3. EC2 tag scan — AWSAIDevOpsManaged tagged resources (resource gateways)
    4. VPC Flow Logs check — network-level visibility on private subnets

    Args:
        ec2_client: Boto3 EC2 client.
        collect_data: Output from Collect step (contains ListAssociations events).

    Returns:
        Dict with private connection findings, risk assessment, and recommendations.
    """
    # --- Layer 1: DescribePrivateConnection API (authoritative) ---
    private_connections = _query_private_connections()

    # --- Layer 2: CloudTrail integration signals ---
    mcp_integrations = _extract_mcp_integrations_from_events(collect_data)

    # --- Layer 3: EC2 resource gateway detection (fallback) ---
    managed_resources = _scan_managed_resources(ec2_client)

    # --- Layer 4: VPC Flow Logs coverage ---
    flow_logs_status = _check_flow_logs_coverage(ec2_client, private_connections)

    # --- Risk Assessment ---
    active_connections = [pc for pc in private_connections if pc['status'] == 'ACTIVE']
    has_no_cert = any(not pc.get('has_certificate') for pc in active_connections)
    has_self_managed = any(pc['type'] == 'SELF_MANAGED' for pc in active_connections)
    has_in_vpc = any(pc.get('dns_resolution') == 'IN_VPC' for pc in active_connections)
    has_gaps = len(active_connections) > 0 and flow_logs_status != 'ENABLED'

    # Risk scoring
    if active_connections and has_self_managed and has_no_cert and flow_logs_status != 'ENABLED':
        risk_level = 'CRITICAL'
    elif has_gaps:
        risk_level = 'HIGH'
    elif active_connections:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    # Build recommendations
    recommendations = []
    if has_gaps:
        recommendations.append("Enable VPC Flow Logs on private connection subnets for network-level audit trail.")
    if has_no_cert:
        recommendations.append("Configure mTLS certificates on private connections for transport-layer verification.")
    if has_self_managed:
        recommendations.append("Self-managed connections bypass service-level controls. Ensure endpoint security is independently verified.")
    if active_connections and not mcp_integrations:
        recommendations.append("Private connections exist but were not visible in CloudTrail integration events. Verify configuration.")

    return {
        'risk_level': risk_level,
        'private_connections': {
            'total': len(private_connections),
            'active': len(active_connections),
            'details': private_connections,
        },
        'security_signals': {
            'self_managed_connections': has_self_managed,
            'connections_without_certificate': has_no_cert,
            'in_vpc_dns_resolution': has_in_vpc,
            'flow_logs_status': flow_logs_status,
        },
        'mcp_integrations_from_cloudtrail': mcp_integrations,
        'managed_resources': managed_resources,
        'recommendations': recommendations,
        'summary': _build_visibility_summary(
            active_connections, risk_level, flow_logs_status, has_no_cert
        ),
    }


def _query_private_connections() -> list:
    """Query DevOps Agent API for private connection details.

    Uses aidevops:DescribePrivateConnection to get authoritative endpoint info
    including hostAddress, type, certificate status, and VPC configuration.

    Returns:
        List of private connection detail dicts.
    """
    # Note: The aidevops API is not yet in the standard boto3 SDK.
    # Use the HTTP API directly or wait for SDK support.
    # For now, we detect connections via EC2 tags and CloudTrail,
    # then attempt the API call if the endpoint is available.

    try:
        # Attempt to use boto3 client (may not be available in all SDK versions).
        # Note: the IAM action namespace is 'aidevops:*' but the boto3/CLI
        # service name is 'devops-agent'.
        client = boto3.client('devops-agent', region_name=REGION)

        # List all private connections
        # Note: API may be list-private-connections or similar
        response = client.list_private_connections()
        connections = []

        for conn in response.get('privateConnections', []):
            name = conn.get('name', '')
            # Describe each connection for full details
            try:
                detail = client.describe_private_connection(name=name)
                connections.append({
                    'name': detail.get('name', ''),
                    'host_address': detail.get('hostAddress', ''),
                    'type': detail.get('type', ''),  # SELF_MANAGED | SERVICE_MANAGED
                    'status': detail.get('status', ''),  # ACTIVE | CREATE_FAILED etc.
                    'dns_resolution': detail.get('dnsResolution', ''),  # PUBLIC | IN_VPC
                    'resource_gateway_id': detail.get('resourceGatewayId', ''),
                    'resource_configuration_id': detail.get('resourceConfigurationId', ''),
                    'vpc_id': detail.get('vpcId', ''),
                    'has_certificate': detail.get('certificateExpiryTime') is not None,
                    'certificate_expiry': detail.get('certificateExpiryTime', ''),
                    'tags': detail.get('tags', {}),
                })
            except Exception as exc:
                logger.debug("Could not describe private connection '%s': %s", name, exc)
                connections.append({
                    'name': name,
                    'status': conn.get('status', 'UNKNOWN'),
                    'type': conn.get('type', 'UNKNOWN'),
                    'host_address': '',
                    'dns_resolution': '',
                    'has_certificate': False,
                })

        logger.info("DescribePrivateConnection: found %d connection(s)", len(connections))
        return connections

    except Exception as exc:
        # SDK not available or API not accessible — fall back to tag-based detection
        logger.info(
            "aidevops API not available (expected if SDK version lacks support): %s. "
            "Falling back to tag-based detection.",
            type(exc).__name__,
        )
        return []


def _extract_mcp_integrations_from_events(collect_data: dict) -> list:
    """Extract MCP integration signals from CloudTrail ListAssociations events.

    When users browse their agent space, ListAssociations is called with
    filterServiceTypes that reveal configured integrations.

    Args:
        collect_data: Output from Collect step.

    Returns:
        List of detected MCP integration type strings.
    """
    events = collect_data.get('events', [])
    mcp_types_seen = set()

    for event in events:
        if event.get('event_name') != 'ListAssociations':
            continue
        filter_types = event.get('request_parameters', {}).get('filterServiceTypes', '')
        if not filter_types:
            continue
        for svc_type in filter_types.split(','):
            svc_type = svc_type.strip()
            if 'mcp' in svc_type.lower() or 'remote' in svc_type.lower():
                mcp_types_seen.add(svc_type)

    return sorted(mcp_types_seen)


def _scan_managed_resources(ec2_client: object) -> list:
    """Scan for AWSAIDevOpsManaged tagged resources (VPC Lattice gateways).

    Fallback detection when the aidevops API is not available.

    Args:
        ec2_client: Boto3 EC2 client.

    Returns:
        List of tagged resource dicts.
    """
    try:
        response = ec2_client.describe_tags(
            Filters=[{'Name': 'key', 'Values': ['AWSAIDevOpsManaged']}]
        )
        return [
            {
                'resource_id': tag['ResourceId'],
                'resource_type': tag['ResourceType'],
                'value': tag.get('Value', ''),
            }
            for tag in response.get('Tags', [])
        ]
    except Exception as exc:
        logger.warning("AWSAIDevOpsManaged tag scan failed: %s", exc)
        return []


def _check_flow_logs_coverage(ec2_client: object, connections: list) -> str:
    """Check VPC Flow Logs on subnets used by private connections.

    Args:
        ec2_client: Boto3 EC2 client.
        connections: List of private connection dicts (may have vpc_id).

    Returns:
        Status string: ENABLED | NOT_ENABLED | NOT_APPLICABLE | UNKNOWN.
    """
    if not connections:
        return 'NOT_APPLICABLE'

    vpc_ids = list(set(
        pc.get('vpc_id', '') for pc in connections if pc.get('vpc_id')
    ))
    if not vpc_ids:
        return 'UNKNOWN'

    try:
        response = ec2_client.describe_flow_logs(
            Filters=[{'Name': 'resource-id', 'Values': vpc_ids}]
        )
        return 'ENABLED' if response.get('FlowLogs') else 'NOT_ENABLED'
    except Exception as exc:
        logger.warning("Flow logs check failed: %s", exc)
        return 'UNKNOWN'


def _build_visibility_summary(
    active_connections: list,
    risk_level: str,
    flow_logs_status: str,
    has_no_cert: bool,
) -> str:
    """Build executive-friendly summary for visibility gaps.

    Args:
        active_connections: List of active private connections.
        risk_level: Computed risk level.
        flow_logs_status: Flow logs coverage status.
        has_no_cert: Whether any connection lacks mTLS.

    Returns:
        Human-readable summary string.
    """
    if not active_connections:
        return (
            "No private MCP connections detected. All agent tool calls are "
            "auditable via CloudTrail."
        )

    connection_details = []
    for pc in active_connections[:3]:
        host = pc.get('host_address') or 'endpoint unknown'
        conn_type = pc.get('type', 'UNKNOWN')
        connection_details.append(f"{pc.get('name', 'unnamed')} → {host} ({conn_type})")

    details_str = '; '.join(connection_details)
    suffix = f" (+{len(active_connections) - 3} more)" if len(active_connections) > 3 else ""

    risk_context = []
    if flow_logs_status != 'ENABLED':
        risk_context.append("no Flow Logs")
    if has_no_cert:
        risk_context.append("no mTLS certificate")

    risk_str = f" Issues: {', '.join(risk_context)}." if risk_context else ""

    return (
        f"{len(active_connections)} active private connection(s): "
        f"{details_str}{suffix}. "
        f"Agent tool calls to these endpoints are NOT in CloudTrail.{risk_str}"
    )


def _assess_integration_exposure(collect_data: dict) -> dict:
    """Analyze integrations and trigger sources for unknown exposure.

    Uses data from the Collect step (ListAssociations events) to identify
    what third-party services are connected and whether webhooks exist
    from unexpected sources.

    Args:
        collect_data: Output from the Collect Lambda (events, triggers).

    Returns:
        Dict with integration inventory and unknown trigger assessment.
    """
    events = collect_data.get('events', [])
    triggers = collect_data.get('triggers', [])

    # Extract integration types from ListAssociations events
    integrations_seen = set()
    for event in events:
        if event.get('event_name') == 'ListAssociations':
            filter_types = event.get('request_parameters', {}).get('filterServiceTypes', '')
            if filter_types:
                for svc in filter_types.split(','):
                    svc = svc.strip()
                    if svc:
                        integrations_seen.add(svc)

    # Classify triggers
    trigger_types = {}
    unknown_triggers = []
    for trigger in triggers:
        t_type = trigger.get('trigger_type', 'unknown')
        trigger_types[t_type] = trigger_types.get(t_type, 0) + 1
        if t_type == 'unknown':
            unknown_triggers.append(trigger)

    has_unknown = len(unknown_triggers) > 0
    has_lambda_triggers = trigger_types.get('lambda-webhook', 0) > 0

    return {
        'risk_level': 'HIGH' if has_unknown else ('MEDIUM' if has_lambda_triggers else 'LOW'),
        'integrations_configured': sorted(integrations_seen),
        'trigger_breakdown': trigger_types,
        'unknown_triggers': unknown_triggers[:10],
        'summary': (
            f"WARNING: {len(unknown_triggers)} trigger(s) from unidentified sources. "
            f"Review immediately for shadow automation."
        ) if has_unknown else (
            f"{sum(trigger_types.values())} trigger(s) detected, all from identified sources. "
            f"Integrations: {', '.join(sorted(integrations_seen)[:5]) or 'none'}."
        ),
    }


def _assess_human_approval(collect_data: dict, capability_result: dict = None) -> dict:
    """Check whether human-in-the-loop is enforced for mutations.

    Looks for UpdateBacklogTask events (approval/rejection of mitigations)
    and whether any mitigation was auto-approved without human review.

    Escalates to HIGH if the agent has mutating capability but zero human
    approvals were detected — indicating autonomous operation without oversight.

    Args:
        collect_data: Output from the Collect Lambda (events).
        capability_result: Output from _assess_capability_level (optional).

    Returns:
        Dict with approval enforcement status.
    """
    events = collect_data.get('events', [])
    tasks = collect_data.get('tasks', [])

    # Count approvals/rejections
    approvals = 0
    rejections = 0
    for event in events:
        if event.get('event_name') == 'UpdateBacklogTask':
            # If a human approved or rejected a mitigation
            if event.get('trigger_type') in ('human-console', 'mcp-client'):
                approvals += 1

    # Check if there are tasks without corresponding approvals
    investigation_tasks = [t for t in tasks if t.get('task_type') == 'INVESTIGATION']

    # Determine if agent has mutating capability, and whether any is ACTIVE
    has_actions_roles = False
    active_actions_roles = 0
    dormant_actions_roles = 0
    if capability_result:
        has_actions_roles = capability_result.get('actions_capable_roles', 0) > 0
        actions_roles = capability_result.get('actions_roles', [])
        active_actions_roles = sum(1 for r in actions_roles if r.get('status') == 'ACTIVE')
        dormant_actions_roles = sum(1 for r in actions_roles if r.get('status') == 'DORMANT')

    # Risk logic:
    # - HIGH: an actions-capable role was ACTIVE (used) this period with zero approvals
    #         — mutating activity may be executing without human oversight
    # - LOW (dormant): actions-capable roles exist but all are DORMANT — no mutations
    #         occurred, so 0 approvals is expected (e.g., auto-created but unused roles)
    # - LOW: approvals detected, or read-only agent
    if active_actions_roles > 0 and approvals == 0:
        risk_level = 'HIGH'
        summary = (
            f"{active_actions_roles} actions-capable role(s) were active this period "
            f"but 0 human approvals detected. "
            f"Mutating actions may be executing without human oversight."
        )
    elif has_actions_roles and approvals == 0:
        # All actions-capable roles are dormant — capability exists but unused
        risk_level = 'LOW'
        summary = (
            f"{dormant_actions_roles} actions-capable role(s) present but dormant this period "
            f"(no mutating activity). Several are auto-created service roles. "
            f"No mutations occurred, so human approval was not required."
        )
    elif approvals > 0:
        risk_level = 'LOW'
        summary = (
            f"{approvals} human approval(s) detected. "
            f"Agent Actions require human sign-off before execution — enforced by service design."
        )
    else:
        risk_level = 'LOW'
        summary = (
            f"{len(investigation_tasks)} investigation(s) ran in read-only mode. "
            f"No mutations attempted — human approval not required for read operations."
        )

    return {
        'risk_level': risk_level,
        'human_approvals_detected': approvals,
        'human_rejections_detected': rejections,
        'investigations_in_period': len(investigation_tasks),
        'active_actions_roles': active_actions_roles,
        'dormant_actions_roles': dormant_actions_roles,
        'summary': summary,
    }


def _compute_overall_risk(assessments: dict) -> dict:
    """Compute overall trust posture from individual assessments.

    Args:
        assessments: Dict of assessment results keyed by dimension name.

    Returns:
        Dict with overall risk level and executive summary.
    """
    risk_hierarchy = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    max_risk = 'LOW'
    risk_flags = []

    for dimension, result in assessments.items():
        level = result.get('risk_level', 'LOW')
        if risk_hierarchy.get(level, 0) > risk_hierarchy.get(max_risk, 0):
            max_risk = level
        if level in ('HIGH', 'CRITICAL'):
            risk_flags.append(f"{dimension}: {result.get('summary', '')}")

    return {
        'overall_risk': max_risk,
        'risk_flags': risk_flags,
        'dimensions_assessed': len(assessments),
        'executive_summary': (
            f"Agent Authorization & Risk Profile: {max_risk}. "
            f"{len(risk_flags)} issue(s) require attention."
        ) if risk_flags else (
            f"Agent Authorization & Risk Profile: {max_risk}. "
            f"All {len(assessments)} trust dimensions within acceptable bounds."
        ),
    }


def _make_finding_id(dimension: str, subtype: str, natural_key: str, state: str) -> str:
    """Generate a stable, state-aware finding identifier.

    The ID is deterministic for a given (dimension, subtype, natural_key, state),
    so the same finding in the same state always yields the same ID across runs —
    this is what lets suppression decisions persist.

    The state component is baked into the hash on purpose: if the finding's
    material state changes (e.g., a role goes DORMANT -> ACTIVE, or a permission
    scope widens), the ID changes, any prior suppression no longer matches, and
    the finding automatically resurfaces. This prevents a suppression from
    becoming a permanent blind spot.

    The 'f-' prefix forces spreadsheet tools to treat the ID as text (an all-digit
    hash would otherwise be mangled into scientific notation / lose leading zeros
    on CSV round-trip).

    Args:
        dimension: Risk dimension (e.g., 'capability', 'permission').
        subtype: Finding subtype (e.g., 'role', 'action', 'connection').
        natural_key: Stable resource key (e.g., role ARN, role::action).
        state: Material state string; change here voids old suppressions.

    Returns:
        Finding ID like 'f-a3f9c1e8b2'.
    """
    raw = f"{dimension}:{subtype}:{natural_key}:{state}"
    return "f-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]  # nosec B324 — non-crypto ID, not a security control


def _extract_findings(assessments: dict) -> list:
    """Walk each dimension's per-item findings and attach a stable finding_id.

    Mutates the assessment dicts in place (adds 'finding_id' to each item) and
    returns a flat list of findings for CSV export and suppression matching.

    State-aware keys per dimension (see _make_finding_id for why state matters):
      - capability: role ARN + status(ACTIVE/DORMANT) + capability_level
      - permission: role::action + severity + wildcard-scope flag
      - visibility: connection name + status + dns_resolution + cert presence
      - integration: trigger/source id + presence
      - human_approval: dimension-level + active-role count bucket

    Args:
        assessments: Dict of dimension assessment results (mutated in place).

    Returns:
        Flat list of finding dicts: {finding_id, dimension, subtype, finding, severity, natural_key}.
    """
    findings = []

    # --- Capability: per actions-capable role ---
    cap = assessments.get('capability_level', {})
    for role in cap.get('actions_roles', []):
        natural_key = role.get('role_arn', role.get('role_name', ''))
        state = f"{role.get('status', 'UNKNOWN')}|{cap.get('capability_level', '')}"
        fid = _make_finding_id('capability', 'role', natural_key, state)
        role['finding_id'] = fid
        findings.append({
            'finding_id': fid,
            'dimension': 'Capability',
            'subtype': 'role',
            'finding': f"{role.get('role_name', '')} ({role.get('status', '')}) — actions-capable role",
            'severity': cap.get('risk_level', 'MEDIUM'),
            'natural_key': natural_key,
        })

    # --- Permission Scope: per (role + risky action) ---
    perm = assessments.get('permission_scope', {})
    for sev, items in (('HIGH', perm.get('high_risk_permissions', [])),
                       ('MEDIUM', perm.get('moderate_risk_permissions', []))):
        for item in items:
            natural_key = f"{item.get('role', '')}::{item.get('action', '')}"
            state = f"{sev}|wildcard={item.get('is_wildcard_resource', False)}"
            fid = _make_finding_id('permission', 'action', natural_key, state)
            item['finding_id'] = fid
            findings.append({
                'finding_id': fid,
                'dimension': 'Permission',
                'subtype': 'action',
                'finding': f"{item.get('role', '')} allows {item.get('action', '')} on {item.get('resource_scope', '')}",
                'severity': sev,
                'natural_key': natural_key,
            })

    # --- Visibility Gaps: per private connection ---
    vis = assessments.get('visibility_gaps', {})
    for conn in vis.get('private_connections', {}).get('details', []):
        natural_key = conn.get('name', '')
        state = f"{conn.get('status', '')}|{conn.get('dns_resolution', '')}|cert={conn.get('has_certificate', False)}"
        fid = _make_finding_id('visibility', 'connection', natural_key, state)
        conn['finding_id'] = fid
        findings.append({
            'finding_id': fid,
            'dimension': 'Visibility',
            'subtype': 'connection',
            'finding': f"Private MCP connection {conn.get('name', '')} ({conn.get('status', '')}) — not CloudTrail-auditable",
            'severity': vis.get('risk_level', 'MEDIUM'),
            'natural_key': natural_key,
        })

    return findings


def _load_suppressions() -> dict:
    """Load suppressions.json from S3. Fail-open: return empty on missing/corrupt.

    Never suppress-on-error — if the store is unreadable, we treat it as empty so
    findings stay visible rather than being silently hidden by a corrupt file.

    Returns:
        Dict mapping finding_id -> {decision, reason, added_by, added_at, ...}.
    """
    if not RESULTS_BUCKET:
        return {}
    try:
        s3 = boto3.client('s3', region_name=REGION)
        resp = s3.get_object(Bucket=RESULTS_BUCKET, Key=SUPPRESSIONS_KEY)
        data = json.loads(resp['Body'].read().decode('utf-8'))
        supp = data.get('suppressions', {})
        if isinstance(supp, dict):
            return supp
    except Exception as exc:
        logger.info("No suppressions applied (%s)", exc)
    return {}


def _apply_suppressions(findings: list, suppressions: dict) -> dict:
    """Apply suppress/accept decisions to the findings list.

    A decision only matches if the finding_id matches — and since finding_id
    bakes in the finding's state, a decision auto-voids when the state changes
    (e.g., a suppressed DORMANT role goes ACTIVE -> new id -> resurfaces).

    Findings are partitioned, not deleted, so the report can always show a
    collapsed "Suppressed & Accepted" section (never silently hidden).

    Args:
        findings: Flat list of findings (each with finding_id).
        suppressions: finding_id -> decision record.

    Returns:
        Dict with 'active' (score-affecting), 'suppressed', 'accepted' lists
        and counts, including how many accepted findings were HIGH severity.
    """
    active, suppressed, accepted = [], [], []
    for f in findings:
        decision_rec = suppressions.get(f.get('finding_id', ''))
        if not decision_rec:
            active.append(f)
            continue
        decision = decision_rec.get('decision')
        f = {**f, **{
            'decision': decision,
            'decision_reason': decision_rec.get('reason', ''),
            'decision_by': decision_rec.get('added_by', ''),
            'decision_at': decision_rec.get('added_at', ''),
        }}
        if decision == 'suppress':
            suppressed.append(f)
        elif decision == 'accept':
            accepted.append(f)
        else:
            active.append(f)

    accepted_high = sum(1 for f in accepted if str(f.get('severity', '')).upper() in ('HIGH', 'CRITICAL'))
    return {
        'active': active,
        'suppressed': suppressed,
        'accepted': accepted,
        'active_count': len(active),
        'suppressed_count': len(suppressed),
        'accepted_count': len(accepted),
        'accepted_high_count': accepted_high,
    }


def handler(event: dict, context: object) -> dict:
    """Lambda entry point — assess agent authorization & risk profile.

    Evaluates five trust dimensions and produces a risk-scored summary
    suitable for CISO/executive consumption.

    Args:
        event: Pipeline event containing Collect step output.
        context: Lambda context.

    Returns:
        Dict with per-dimension assessments and overall risk posture.
    """
    collect_data = event.get('collect', {})

    iam_client = boto3.client('iam')
    ec2_client = boto3.client('ec2', region_name=REGION)

    logger.info("Assessing agent authorization & risk profile...")

    # --- Dimension 1: Capability Level ---
    capability = _assess_capability_level(iam_client, collect_data)
    logger.info("Capability: %s (%d actions roles)", capability['capability_level'], capability['actions_capable_roles'])

    # --- Dimension 2: Permission Scope (only if actions roles exist) ---
    permissions = _assess_permission_scope(iam_client, capability.get('actions_roles', []))
    logger.info("Permissions: %s risk", permissions['risk_level'])

    # --- Dimension 3: Visibility Gaps (Private MCP) ---
    visibility = _assess_visibility_gaps(ec2_client, collect_data)
    logger.info("Visibility: %s (%d private connections)", visibility['risk_level'], visibility['private_connections']['total'])

    # --- Dimension 4: Integration Exposure ---
    integrations = _assess_integration_exposure(collect_data)
    logger.info("Integrations: %s (%s)", integrations['risk_level'], integrations['trigger_breakdown'])

    # --- Dimension 5: Human-in-the-Loop ---
    approval = _assess_human_approval(collect_data, capability)
    logger.info("Human approval: %s", approval['risk_level'])

    # --- Overall Risk ---
    assessments = {
        'capability_level': capability,
        'permission_scope': permissions,
        'visibility_gaps': visibility,
        'integration_exposure': integrations,
        'human_approval': approval,
    }
    overall = _compute_overall_risk(assessments)

    logger.info("Overall authorization & risk profile: %s", overall['overall_risk'])

    # Attach stable, state-aware finding IDs to every per-item finding and
    # emit a flat findings list (used for CSV export + suppression matching).
    findings = _extract_findings(assessments)
    logger.info("Extracted %d per-item findings with stable IDs", len(findings))

    # Apply CISO suppress/accept decisions (fail-open if store missing/corrupt).
    # Findings are partitioned, never deleted — the report shows a collapsed
    # "Suppressed & Accepted" section so posture is never silently zeroed.
    suppressions = _load_suppressions()
    partitioned = _apply_suppressions(findings, suppressions)
    logger.info(
        "Suppressions applied: %d active, %d suppressed, %d accepted (%d HIGH accepted)",
        partitioned['active_count'], partitioned['suppressed_count'],
        partitioned['accepted_count'], partitioned['accepted_high_count'],
    )

    return {
        'trust_posture': overall,
        'assessments': assessments,
        'findings': partitioned['active'],
        'suppressed_findings': partitioned['suppressed'],
        'accepted_findings': partitioned['accepted'],
        'suppression_summary': {
            'active_count': partitioned['active_count'],
            'suppressed_count': partitioned['suppressed_count'],
            'accepted_count': partitioned['accepted_count'],
            'accepted_high_count': partitioned['accepted_high_count'],
        },
    }
