# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Shared test fixtures and configuration for AgentAudit test suite.

Provides:
- Environment variable setup for all Lambda functions
- Mocked AWS services (S3, IAM, SNS, Athena, CloudTrail, CloudWatch)
- Synthetic data fixtures modeled on representative AI-agent usage patterns
  (all identifiers — account IDs, usernames, IPs, ARNs — are synthetic placeholders)
- Common helpers for building CloudTrail events and CUR rows
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

# Add function directories to path for imports
FUNCTIONS_DIR = os.path.join(os.path.dirname(__file__), '..', 'functions')
for func_dir in ['collect', 'enrich', 'compliance', 'aggregate', 'analyze', 'report', 'feedback']:
    sys.path.insert(0, os.path.join(FUNCTIONS_DIR, func_dir))


import importlib.util


def _load_function_module(func_name):
    """Load a specific function's app.py by explicit path."""
    module_path = os.path.join(FUNCTIONS_DIR, func_name, 'app.py')
    spec = importlib.util.spec_from_file_location(f'{func_name}_app', module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def collect_app():
    """Load collect/app.py module."""
    return _load_function_module('collect')


@pytest.fixture
def enrich_app():
    """Load enrich/app.py module."""
    return _load_function_module('enrich')


@pytest.fixture
def analyze_app():
    """Load analyze/app.py module."""
    return _load_function_module('analyze')


@pytest.fixture
def report_app_module():
    """Load report/app.py module."""
    return _load_function_module('report')


@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    """Set environment variables required by all Lambda functions."""
    env_vars = {
        'REGION': 'us-east-1',
        'AGENT_TYPES': 'devops',
        'AGENT_ROLE_ARNS': '',
        'VENDED_LOG_GROUP': '/aws/vendedlogs/aidevops/agentspace/APPLICATION_LOGS/test-space',
        'CUR_DATABASE': 'test_cur_db',
        'CUR_TABLE': 'test_cur_table',
        'ATHENA_OUTPUT_BUCKET': 'test-athena-output',
        'CUR_SOURCE_BUCKET': 'test-cur-source',
        'ATHENA_WORKGROUP': 'primary',
        'MONTHLY_ES_CHARGE': '5000',
        'BEDROCK_MODEL_ID': 'us.anthropic.claude-sonnet-4-6',
        'RESULTS_BUCKET': 'agentaudit-results-test',
        'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:agentaudit-reports',
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)


# --- Synthetic CloudTrail Event Fixtures ---
# Modeled on representative CloudTrail event structures (all identifiers synthetic)

@pytest.fixture
def cloudtrail_create_backlog_task():
    """Sample CreateBacklogTask event structure.."""
    return {
        'EventId': 'test-event-001',
        'EventName': 'CreateBacklogTask',
        'EventTime': datetime(2026, 8, 8, 16, 43, 0, tzinfo=timezone.utc),
        'EventSource': 'aidevops.amazonaws.com',
        'Username': 'testuser1',
        'CloudTrailEvent': json.dumps({
            'eventVersion': '1.11',
            'userIdentity': {
                'type': 'AssumedRole',
                'principalId': 'AROAEXAMPLEID:testuser1',
                'arn': 'arn:aws:sts::111111111111:assumed-role/DevOpsAgentRole-WebappAdmin-d33850ed/testuser1',
                'accountId': '111111111111',
                'accessKeyId': 'ASIAEXAMPLEKEY',
                'sessionContext': {
                    'sessionIssuer': {
                        'type': 'Role',
                        'principalId': 'AROAEXAMPLEID',
                        'arn': 'arn:aws:iam::111111111111:role/DevOpsAgentRole-WebappAdmin-d33850ed',
                        'accountId': '111111111111',
                        'userName': 'DevOpsAgentRole-WebappAdmin-d33850ed',
                    },
                    'attributes': {
                        'creationDate': '2026-08-08T16:42:00Z',
                        'mfaAuthenticated': 'false',
                    },
                },
            },
            'eventTime': '2026-08-08T16:43:00Z',
            'eventSource': 'aidevops.amazonaws.com',
            'eventName': 'CreateBacklogTask',
            'awsRegion': 'us-east-1',
            'sourceIPAddress': '192.0.2.64',
            'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'requestParameters': {
                'agentSpaceId': 'd33850ed-1a07-4946-8127-d5a1a92daf7f',
                'taskType': 'INVESTIGATION',
                'priority': 'MEDIUM',
            },
            'responseElements': {
                'task': {
                    'taskId': '7c176884-test',
                    'executionId': 'exec-001',
                    'agentSpaceId': 'd33850ed-1a07-4946-8127-d5a1a92daf7f',
                    'taskType': 'INVESTIGATION',
                    'priority': 'MEDIUM',
                    'status': 'PENDING_START',
                },
            },
            'requestID': 'req-001',
            'eventID': 'test-event-001',
            'readOnly': False,
            'eventType': 'AwsApiCall',
            'managementEvent': True,
            'recipientAccountId': '111111111111',
            'eventCategory': 'Management',
            'sessionCredentialFromConsole': 'true',
        }),
        'Resources': [
            {'ResourceType': 'AWS::AIDevOps::AgentSpace', 'ResourceName': 'd33850ed-1a07-4946-8127-d5a1a92daf7f'},
        ],
    }


@pytest.fixture
def cloudtrail_create_chat():
    """Synthetic CreateChat event structure (representative)."""
    return {
        'EventId': 'test-event-002',
        'EventName': 'CreateChat',
        'EventTime': datetime(2026, 7, 31, 18, 0, 0, tzinfo=timezone.utc),
        'EventSource': 'aidevops.amazonaws.com',
        'Username': 'testuser2',
        'CloudTrailEvent': json.dumps({
            'eventVersion': '1.11',
            'userIdentity': {
                'type': 'AssumedRole',
                'principalId': 'AROAEXAMPLEID:testuser2',
                'arn': 'arn:aws:sts::333333333333:assumed-role/SampleDevRole/testuser2',
                'accountId': '333333333333',
                'accessKeyId': 'ASIAEXAMPLE2',
                'sessionContext': {
                    'sessionIssuer': {
                        'type': 'Role',
                        'arn': 'arn:aws:iam::333333333333:role/SampleDevRole',
                        'accountId': '333333333333',
                        'userName': 'SampleDevRole',
                    },
                    'attributes': {'creationDate': '2026-07-31T17:59:00Z', 'mfaAuthenticated': 'false'},
                },
            },
            'eventTime': '2026-07-31T18:00:00Z',
            'eventSource': 'aidevops.amazonaws.com',
            'eventName': 'CreateChat',
            'awsRegion': 'us-east-1',
            'sourceIPAddress': '198.51.100.251',
            'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
            'requestParameters': {'agentSpaceId': '7e10c02e-17dd-4184-ac89-a568e734eada'},
            'responseElements': {'executionId': 'exec-chat-001'},
            'requestID': 'req-002',
            'eventID': 'test-event-002',
            'readOnly': False,
            'resources': [{'ARN': 'arn:aws:aidevops:us-east-1:333333333333:agentspace/7e10c02e-17dd-4184-ac89-a568e734eada', 'type': 'AWS::AIDevOps::AgentSpace'}],
        }),
        'Resources': [
            {'ResourceType': 'AWS::AIDevOps::AgentSpace', 'ResourceName': '7e10c02e-17dd-4184-ac89-a568e734eada'},
        ],
    }


@pytest.fixture
def cloudtrail_lambda_webhook():
    """Lambda webhook trigger event from Lambda webhook trigger event (automated).."""
    return {
        'EventId': 'test-event-003',
        'EventName': 'CreateBacklogTask',
        'EventTime': datetime(2026, 8, 8, 3, 12, 0, tzinfo=timezone.utc),
        'EventSource': 'aidevops.amazonaws.com',
        'Username': 'example-system-health-devops-agent',
        'CloudTrailEvent': json.dumps({
            'eventVersion': '1.11',
            'userIdentity': {
                'type': 'AssumedRole',
                'principalId': 'AROAEXAMPLE3:example-system-health-devops-agent',
                'arn': 'arn:aws:sts::222222222222:assumed-role/example-app-health-agent-role/example-system-health-devops-agent',
                'accountId': '222222222222',
                'sessionContext': {
                    'sessionIssuer': {
                        'type': 'Role',
                        'arn': 'arn:aws:iam::222222222222:role/example-app-health-agent-role',
                        'accountId': '222222222222',
                        'userName': 'example-app-health-agent-role',
                    },
                    'attributes': {'creationDate': '2026-08-08T03:12:00Z', 'mfaAuthenticated': 'false'},
                },
            },
            'eventTime': '2026-08-08T03:12:00Z',
            'eventSource': 'aidevops.amazonaws.com',
            'eventName': 'CreateBacklogTask',
            'awsRegion': 'us-east-1',
            'sourceIPAddress': '10.0.1.50',
            'userAgent': 'exec-env/AWS_Lambda_python3.12',
            'requestParameters': {
                'agentSpaceId': '498a79ac-3803-4866-ba88-754d1f67abce',
                'taskType': 'INVESTIGATION',
                'priority': 'HIGH',
            },
            'responseElements': {
                'task': {
                    'taskId': 'task-lambda-001',
                    'executionId': 'exec-lambda-001',
                    'agentSpaceId': '498a79ac-3803-4866-ba88-754d1f67abce',
                    'taskType': 'INVESTIGATION',
                    'priority': 'HIGH',
                    'status': 'PENDING_START',
                },
            },
            'requestID': 'req-003',
            'eventID': 'test-event-003',
            'readOnly': False,
        }),
        'Resources': [],
    }


# --- CUR Data Fixtures ---

@pytest.fixture
def cur_daily_trend():
    """Daily cost trend data (simulates Athena query output)."""
    trend = []
    for day in range(1, 9):
        trend.append({'date': f'2026-08-0{day}', 'operation': 'POWER_CHAT', 'hours': 20.8, 'cost': 625.0})
        trend.append({'date': f'2026-08-0{day}', 'operation': 'TRIAGE', 'hours': 6.0, 'cost': 180.0})
    return trend


@pytest.fixture
def period_end():
    """Standard report period end for testing."""
    return datetime(2026, 8, 8, 19, 0, 0, tzinfo=timezone.utc)


# --- IAM Fixtures ---

@pytest.fixture
def iam_roles_response():
    """Mock IAM ListRoles response with agent trust relationships."""
    return {
        'Roles': [
            {
                'RoleName': 'DevOpsAgentRole-AgentSpace-d33850ed',
                'Arn': 'arn:aws:iam::111111111111:role/DevOpsAgentRole-AgentSpace-d33850ed',
                'AssumeRolePolicyDocument': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'Service': 'aidevops.amazonaws.com'},
                        'Action': 'sts:AssumeRole',
                    }],
                },
            },
            {
                'RoleName': 'DevOpsAgentRole-WebappAdmin-d33850ed',
                'Arn': 'arn:aws:iam::111111111111:role/DevOpsAgentRole-WebappAdmin-d33850ed',
                'AssumeRolePolicyDocument': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'Service': 'aidevops.amazonaws.com'},
                        'Action': 'sts:AssumeRole',
                    }],
                },
            },
            {
                'RoleName': 'UnrelatedRole',
                'Arn': 'arn:aws:iam::111111111111:role/UnrelatedRole',
                'AssumeRolePolicyDocument': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'Service': 'lambda.amazonaws.com'},
                        'Action': 'sts:AssumeRole',
                    }],
                },
            },
        ],
    }
