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

    # Manual overrides take precedence
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

    result = {
        'discovered_roles': len(discovered_roles),
        'agent_space_roles': [r['role_arn'] for r in agent_space_roles],
        'webapp_roles': [r['role_arn'] for r in webapp_roles],
        'custom_roles': [r['role_arn'] for r in other_roles],
        'manual_overrides': manual_arns,
        'audit_target_roles': manual_arns if manual_arns else [r['role_arn'] for r in agent_space_roles + other_roles],
    }

    logger.info("Discovered %d roles (%d agent-space, %d webapp, %d custom). Audit targets: %d",
                len(discovered_roles), len(agent_space_roles), len(webapp_roles),
                len(other_roles), len(result['audit_target_roles']))

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
