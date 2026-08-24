# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for the Discover function — agent role discovery and audit-target scoping.

Focus: AGENT_ROLE_ARNS must AUGMENT auto-discovery, never replace/narrow it.
Audit coverage should always be >= what discovery finds, so a manual entry can
never silently shrink the org-wide governance scope.

IAM is stubbed with unittest.mock (no moto/AWS dependency), matching the rest
of the suite's dependency-free style.
"""
import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_DISCOVER_DIR = os.path.join(os.path.dirname(__file__), '..', 'functions', 'discover')
sys.path.insert(0, _DISCOVER_DIR)


def _load_discover():
    spec = importlib.util.spec_from_file_location(
        'discover_app', os.path.join(_DISCOVER_DIR, 'app.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _iam_stub_with_role(role_name, role_arn):
    """Return a boto3-like IAM client stub whose paginator yields one agent role
    (trusting aidevops.amazonaws.com)."""
    page = {'Roles': [{
        'RoleName': role_name,
        'Arn': role_arn,
        'AssumeRolePolicyDocument': {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'aidevops.amazonaws.com'},
                'Action': 'sts:AssumeRole',
            }],
        },
    }]}
    paginator = MagicMock()
    paginator.paginate.return_value = [page]
    client = MagicMock()
    client.get_paginator.return_value = paginator
    return client


class TestAuditTargetScoping:
    def test_auto_discovers_agent_roles_when_no_manual(self, monkeypatch):
        monkeypatch.setenv('AGENT_ROLE_ARNS', '')
        arn = 'arn:aws:iam::111111111111:role/DevOpsAgentRole-space-abc'
        stub = _iam_stub_with_role('DevOpsAgentRole-space-abc', arn)
        with patch('boto3.client', return_value=stub):
            result = _load_discover().handler({}, None)
        assert arn in result['audit_target_roles']
        assert result['manual_additions'] == []

    def test_manual_arns_augment_not_replace(self, monkeypatch):
        # A discovered agent role AND a manual ARN → both present (union).
        discovered = 'arn:aws:iam::111111111111:role/DevOpsAgentRole-space-abc'
        manual = 'arn:aws:iam::111111111111:role/custom-agent-role'
        monkeypatch.setenv('AGENT_ROLE_ARNS', manual)
        stub = _iam_stub_with_role('DevOpsAgentRole-space-abc', discovered)
        with patch('boto3.client', return_value=stub):
            result = _load_discover().handler({}, None)
        assert discovered in result['audit_target_roles'], \
            "manual ARN must not remove auto-discovered roles (no silent narrowing)"
        assert manual in result['audit_target_roles'], \
            "manual ARN must be added to the audit targets"
        assert result['manual_additions'] == [manual]

    def test_targets_deduplicated(self, monkeypatch):
        # Supplying the same ARN discovery already found must not duplicate it.
        discovered = 'arn:aws:iam::111111111111:role/DevOpsAgentRole-space-abc'
        monkeypatch.setenv('AGENT_ROLE_ARNS', discovered)
        stub = _iam_stub_with_role('DevOpsAgentRole-space-abc', discovered)
        with patch('boto3.client', return_value=stub):
            result = _load_discover().handler({}, None)
        assert result['audit_target_roles'].count(discovered) == 1
