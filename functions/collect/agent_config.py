# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Agent configuration — defines supported agents and their data source mappings.

AgentAudit supports multiple AWS AI agents. Each agent has different:
- CloudTrail event sources and event names
- CUR product codes and operation types
- IAM trust principals for role discovery
- CloudWatch metric namespaces
- Vended log group paths

Customers select which agent(s) to audit via the AgentTypes parameter:
- 'devops' — AWS DevOps Agent only
- 'security' — AWS Security Agent only
- 'both' — Both agents in a single report

This module provides the configuration for each agent type, enabling the
pipeline functions to work generically across agent types.
"""

import os
from typing import NamedTuple

AGENT_TYPES_CONFIG = os.environ.get('AGENT_TYPES', 'devops')


class AgentConfig(NamedTuple):
    """Configuration for a single agent type."""

    name: str
    display_name: str
    event_source: str
    iam_trust_principal: str
    cloudwatch_namespace: str
    cur_product_code: str
    vended_log_prefix: str
    trigger_events: frozenset
    config_events: frozenset


# --- AWS DevOps Agent ---
DEVOPS_AGENT = AgentConfig(
    name='devops',
    display_name='AWS DevOps Agent',
    event_source='aidevops.amazonaws.com',
    iam_trust_principal='aidevops.amazonaws.com',
    cloudwatch_namespace='AWS/AIDevOps',
    cur_product_code='DevOpsAgent',
    vended_log_prefix='/aws/vendedlogs/aidevops',
    trigger_events=frozenset({
        'CreateBacklogTask',
        'CreateChat',
        'CreateOneTimeLoginSession',
    }),
    config_events=frozenset({
        'UpdateAssociation',
        'UpdateAgentSpace',
        'CreateAgentSpace',
        'DeleteAgentSpace',
        'TagResource',
    }),
)

# --- AWS Security Agent ---
SECURITY_AGENT = AgentConfig(
    name='security',
    display_name='AWS Security Agent',
    event_source='securityagent.amazonaws.com',
    iam_trust_principal='securityagent.amazonaws.com',
    cloudwatch_namespace='AWS/SecurityAgent',
    cur_product_code='SecAgent',
    vended_log_prefix='/aws/vendedlogs/securityagent',
    trigger_events=frozenset({
        'CreatePentest',
        'StartPentestJob',
        'StartCodeRemediation',
    }),
    config_events=frozenset({
        'UpdatePentest',
        'DeletePentest',
        'CreateIntegration',
        'DeleteIntegration',
    }),
)

# --- Registry ---
AGENT_REGISTRY = {
    'devops': DEVOPS_AGENT,
    'security': SECURITY_AGENT,
}


def get_active_agents() -> list:
    """Get the list of agent configs to audit based on AGENT_TYPES env var.

    Returns:
        List of AgentConfig objects for the configured agent types.
    """
    agent_types = AGENT_TYPES_CONFIG.lower().strip()

    if agent_types == 'both':
        return [DEVOPS_AGENT, SECURITY_AGENT]
    elif agent_types == 'security':
        return [SECURITY_AGENT]
    else:
        return [DEVOPS_AGENT]


def get_all_event_sources() -> list:
    """Get CloudTrail event sources for all active agents.

    Returns:
        List of event source strings to query.
    """
    return [agent.event_source for agent in get_active_agents()]


def get_all_trust_principals() -> list:
    """Get IAM trust principals for all active agents.

    Returns:
        List of service principal strings for role discovery.
    """
    return [agent.iam_trust_principal for agent in get_active_agents()]


def get_all_cur_product_codes() -> list:
    """Get CUR product codes for all active agents.

    Returns:
        List of product code strings for cost queries.
    """
    return [agent.cur_product_code for agent in get_active_agents()]


def get_all_trigger_events() -> frozenset:
    """Get combined trigger event names across all active agents.

    Returns:
        Frozenset of event names that represent work initiation.
    """
    combined = set()
    for agent in get_active_agents():
        combined.update(agent.trigger_events)
    return frozenset(combined)


def classify_event_to_agent(event_source: str) -> str:
    """Map a CloudTrail event source back to an agent display name.

    Args:
        event_source: CloudTrail eventSource value.

    Returns:
        Agent display name or 'Unknown Agent'.
    """
    for agent in AGENT_REGISTRY.values():
        if agent.event_source == event_source:
            return agent.display_name
    return 'Unknown Agent'
