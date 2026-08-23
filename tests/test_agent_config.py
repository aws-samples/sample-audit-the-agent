# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for agent_config module — multi-agent registry and configuration."""

import os
import pytest
from agent_config import (
    DEVOPS_AGENT,
    SECURITY_AGENT,
    AGENT_REGISTRY,
    AgentConfig,
    get_active_agents,
    get_all_event_sources,
    get_all_trust_principals,
    get_all_cur_product_codes,
    get_all_trigger_events,
    classify_event_to_agent,
)


class TestAgentConfigConstants:
    """Test agent configuration values are correct."""

    def test_devops_agent_event_source(self):
        assert DEVOPS_AGENT.event_source == 'aidevops.amazonaws.com'

    def test_security_agent_event_source(self):
        assert SECURITY_AGENT.event_source == 'securityagent.amazonaws.com'

    def test_devops_agent_cur_product_code(self):
        assert DEVOPS_AGENT.cur_product_code == 'DevOpsAgent'

    def test_security_agent_cur_product_code(self):
        assert SECURITY_AGENT.cur_product_code == 'SecAgent'

    def test_devops_trigger_events_include_create_backlog_task(self):
        assert 'CreateBacklogTask' in DEVOPS_AGENT.trigger_events

    def test_devops_trigger_events_include_create_chat(self):
        assert 'CreateChat' in DEVOPS_AGENT.trigger_events

    def test_security_trigger_events_include_create_pentest(self):
        assert 'CreatePentest' in SECURITY_AGENT.trigger_events

    def test_agent_registry_contains_both(self):
        assert 'devops' in AGENT_REGISTRY
        assert 'security' in AGENT_REGISTRY

    def test_agent_config_is_named_tuple(self):
        assert isinstance(DEVOPS_AGENT, AgentConfig)
        assert isinstance(SECURITY_AGENT, AgentConfig)


class TestGetActiveAgents:
    """Test get_active_agents respects AGENT_TYPES env var."""

    def test_devops_only(self, monkeypatch):
        monkeypatch.setenv('AGENT_TYPES', 'devops')
        # Need to reimport to pick up new env
        import importlib
        import agent_config
        importlib.reload(agent_config)
        agents = agent_config.get_active_agents()
        assert len(agents) == 1
        assert agents[0].name == 'devops'

    def test_security_only(self, monkeypatch):
        monkeypatch.setenv('AGENT_TYPES', 'security')
        import importlib
        import agent_config
        importlib.reload(agent_config)
        agents = agent_config.get_active_agents()
        assert len(agents) == 1
        assert agents[0].name == 'security'

    def test_both_agents(self, monkeypatch):
        monkeypatch.setenv('AGENT_TYPES', 'both')
        import importlib
        import agent_config
        importlib.reload(agent_config)
        agents = agent_config.get_active_agents()
        assert len(agents) == 2
        names = {a.name for a in agents}
        assert names == {'devops', 'security'}

    def test_defaults_to_devops(self, monkeypatch):
        monkeypatch.setenv('AGENT_TYPES', 'invalid')
        import importlib
        import agent_config
        importlib.reload(agent_config)
        agents = agent_config.get_active_agents()
        assert len(agents) == 1
        assert agents[0].name == 'devops'


class TestClassifyEventToAgent:
    """Test event-to-agent classification."""

    def test_devops_event_source(self):
        assert classify_event_to_agent('aidevops.amazonaws.com') == 'AWS DevOps Agent'

    def test_security_event_source(self):
        assert classify_event_to_agent('securityagent.amazonaws.com') == 'AWS Security Agent'

    def test_unknown_event_source(self):
        assert classify_event_to_agent('unknown.amazonaws.com') == 'Unknown Agent'

    def test_empty_event_source(self):
        assert classify_event_to_agent('') == 'Unknown Agent'


class TestGetAllTriggerEvents:
    """Test combined trigger events across active agents."""

    def test_devops_triggers(self, monkeypatch):
        monkeypatch.setenv('AGENT_TYPES', 'devops')
        import importlib
        import agent_config
        importlib.reload(agent_config)
        triggers = agent_config.get_all_trigger_events()
        assert 'CreateBacklogTask' in triggers
        assert 'CreateChat' in triggers
        assert 'CreatePentest' not in triggers

    def test_both_triggers(self, monkeypatch):
        monkeypatch.setenv('AGENT_TYPES', 'both')
        import importlib
        import agent_config
        importlib.reload(agent_config)
        triggers = agent_config.get_all_trigger_events()
        assert 'CreateBacklogTask' in triggers
        assert 'CreatePentest' in triggers
        assert 'StartPentestJob' in triggers
