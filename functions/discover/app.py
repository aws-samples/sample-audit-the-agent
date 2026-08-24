# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Discover Lambda — auto-discovers DevOps Agent IAM roles by trust policy.

Scans IAM roles for those trusting aidevops.amazonaws.com as principal.
Customers can use custom role names, so we cannot rely on naming conventions.

Can be run as a pre-step or periodically to update the role list.
"""

import json
import logging
import os
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get('REGION', 'us-east-1')
AGENT_SERVICE_PRINCIPAL = 'aidevops.amazonaws.com'


def handler(event, context):
    """Lambda entry point — discover agent roles by trust policy."""
    iam = boto3.client('iam')

    # Manual role ARNs AUGMENT auto-discovery — they never replace it. Discovery
    # always provides full coverage; manual entries only add roles discovery
    # couldn't find (e.g. custom-named roles). This guarantees audit scope is
    # always >= auto-discovered, so a manual entry can never silently narrow
    # coverage — the right default for an org-wide governance audit.
    manual_arns = [a.strip() for a in os.environ.get('AGENT_ROLE_ARNS', '').split(',') if a.strip()]

    # Auto-discover roles trusting aidevops.amazonaws.com
    discovered_roles = []
    paginator = iam.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page['Roles']:
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            for statement in trust_policy.get('Statement', []):
                principal = statement.get('Principal', {})
                service = principal.get('Service', '')
                # Handle both string and list
                if isinstance(service, str):
                    services = [service]
                else:
                    services = service

                if AGENT_SERVICE_PRINCIPAL in services:
                    discovered_roles.append({
                        'role_name': role['RoleName'],
                        'role_arn': role['Arn'],
                        'role_type': _classify_role(role['RoleName']),
                    })
                    break

    # Classify discovered roles
    agent_space_roles = [r for r in discovered_roles if r['role_type'] == 'agent_space']
    webapp_roles = [r for r in discovered_roles if r['role_type'] == 'webapp']
    other_roles = [r for r in discovered_roles if r['role_type'] == 'custom']

    # Union of auto-discovered audit targets + manual additions, de-duplicated
    # while preserving order (discovered first, then any extra manual ARNs).
    auto_targets = [r['role_arn'] for r in agent_space_roles + other_roles]
    audit_targets = list(dict.fromkeys(auto_targets + manual_arns))

    result = {
        'discovered_roles': len(discovered_roles),
        'agent_space_roles': [r['role_arn'] for r in agent_space_roles],
        'webapp_roles': [r['role_arn'] for r in webapp_roles],
        'custom_roles': [r['role_arn'] for r in other_roles],
        'manual_additions': manual_arns,
        'audit_target_roles': audit_targets,
    }

    logger.info("Discovered %d roles (%d agent-space, %d webapp, %d custom); %d manual addition(s). Audit targets: %d",
                len(discovered_roles), len(agent_space_roles), len(webapp_roles),
                len(other_roles), len(manual_arns), len(result['audit_target_roles']))

    return result


def _classify_role(role_name: str) -> str:
    """Classify role by naming pattern (best-effort)."""
    name_lower = role_name.lower()
    if 'agentspace' in name_lower or 'agent-space' in name_lower:
        return 'agent_space'
    elif 'webapp' in name_lower or 'operator' in name_lower:
        return 'webapp'
    else:
        return 'custom'
