# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for Collect function."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'collect'))
import importlib.util
_spec = importlib.util.spec_from_file_location('collect_app', os.path.join(os.path.dirname(__file__), '..', 'functions', 'collect', 'app.py'))
collect_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collect_app)

import pytest

class TestClassifyTrigger:
    def test_human_console_chrome(self):
        assert collect_app.classify_trigger('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', '192.0.2.64', '') == 'human-console'

    def test_lambda_webhook(self):
        assert collect_app.classify_trigger('exec-env/AWS_Lambda_python3.12', '10.0.1.50', '') == 'lambda-webhook'

    def test_iac_deployment_cloudformation(self):
        assert collect_app.classify_trigger('cloudformation.amazonaws.com', 'cloudformation.amazonaws.com', 'cloudformation.amazonaws.com') == 'iac-deployment'

    def test_mcp_client_node(self):
        assert collect_app.classify_trigger('node', '192.168.1.100', '') == 'mcp-client'

    def test_agent_internal(self):
        assert collect_app.classify_trigger('aidevops.amazonaws.com', 'aidevops.amazonaws.com', 'aidevops.amazonaws.com') == 'agent-internal'

    def test_eventbridge_rule(self):
        assert collect_app.classify_trigger('events.amazonaws.com', 'events.amazonaws.com', 'events.amazonaws.com') == 'eventbridge-rule'

    def test_sdk_programmatic_boto3(self):
        assert collect_app.classify_trigger('Boto3/1.28.0 Python/3.12.0', '203.0.113.50', '') == 'sdk-programmatic'

class TestParseAndExtract:
    def test_parse_create_backlog_task(self, cloudtrail_create_backlog_task):
        event = collect_app._parse_cloudtrail_event(cloudtrail_create_backlog_task)
        assert event['event_name'] == 'CreateBacklogTask'
        assert event['trigger_type'] == 'human-console'
        assert event['agent_type'] == 'AWS DevOps Agent'
        assert event['principal']['human_identity'] == 'testuser1'

    def test_parse_lambda_webhook(self, cloudtrail_lambda_webhook):
        event = collect_app._parse_cloudtrail_event(cloudtrail_lambda_webhook)
        assert event['event_name'] == 'CreateBacklogTask'
        assert event['trigger_type'] == 'lambda-webhook'

    def test_extract_tasks_from_backlog(self, cloudtrail_create_backlog_task):
        parsed = collect_app._parse_cloudtrail_event(cloudtrail_create_backlog_task)
        tasks = collect_app._extract_tasks([parsed])
        assert len(tasks) == 1
        assert tasks[0]['task_id'] == '7c176884-test'
        assert tasks[0]['task_type'] == 'INVESTIGATION'
        assert tasks[0]['triggered_by'] == 'testuser1'

    def test_extract_tasks_skips_read_events(self):
        non_trigger = {'event_name': 'ListAssociations', 'event_source': 'aidevops.amazonaws.com', 'trigger_type': 'agent-internal', 'agent_type': 'AWS DevOps Agent', 'principal': {'human_identity': 'system'}, 'user_agent': 'aidevops.amazonaws.com', 'response_elements': {}, 'request_parameters': {}, 'resources': [], 'event_time': '2026-08-08T16:43:00'}
        tasks = collect_app._extract_tasks([non_trigger])
        assert len(tasks) == 0
