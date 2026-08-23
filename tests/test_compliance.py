# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for Compliance (Authorization & Risk Profile) function."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'compliance'))
import importlib.util
_spec = importlib.util.spec_from_file_location('compliance_app', os.path.join(os.path.dirname(__file__), '..', 'functions', 'compliance', 'app.py'))
compliance_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compliance_app)

import pytest


class TestHumanApprovalRisk:
    """Human approval escalation should key off ACTIVE usage, not dormant capability."""

    def test_active_actions_role_no_approvals_is_high(self):
        capability = {
            'actions_capable_roles': 2,
            'actions_roles': [
                {'role_name': 'r1', 'status': 'ACTIVE'},
                {'role_name': 'r2', 'status': 'DORMANT'},
            ],
        }
        result = compliance_app._assess_human_approval({'events': [], 'tasks': []}, capability)
        assert result['risk_level'] == 'HIGH'
        assert result['active_actions_roles'] == 1

    def test_all_dormant_actions_roles_is_not_high(self):
        # Auto-created but unused roles should NOT drive HIGH
        capability = {
            'actions_capable_roles': 3,
            'actions_roles': [
                {'role_name': 'security-testing-1', 'status': 'DORMANT'},
                {'role_name': 'application-1', 'status': 'DORMANT'},
                {'role_name': 'DevOpsAgentRole-x', 'status': 'DORMANT'},
            ],
        }
        result = compliance_app._assess_human_approval({'events': [], 'tasks': []}, capability)
        assert result['risk_level'] == 'LOW'
        assert result['dormant_actions_roles'] == 3
        assert result['active_actions_roles'] == 0

    def test_approvals_present_is_low(self):
        capability = {
            'actions_capable_roles': 1,
            'actions_roles': [{'role_name': 'r1', 'status': 'ACTIVE'}],
        }
        events = [{'event_name': 'UpdateBacklogTask', 'trigger_type': 'human-console'}]
        result = compliance_app._assess_human_approval({'events': events, 'tasks': []}, capability)
        assert result['risk_level'] == 'LOW'
        assert result['human_approvals_detected'] == 1

    def test_read_only_agent_is_low(self):
        capability = {'actions_capable_roles': 0, 'actions_roles': []}
        result = compliance_app._assess_human_approval({'events': [], 'tasks': []}, capability)
        assert result['risk_level'] == 'LOW'


class TestFindingId:
    """finding_id must be stable for a given state and change when state changes."""

    def test_id_has_text_prefix(self):
        fid = compliance_app._make_finding_id('capability', 'role', 'arn:...:role/x', 'DORMANT|ACTIONS_ENABLED')
        assert fid.startswith('f-')  # forces text in spreadsheets

    def test_id_is_stable_for_same_inputs(self):
        a = compliance_app._make_finding_id('capability', 'role', 'arn:x', 'DORMANT')
        b = compliance_app._make_finding_id('capability', 'role', 'arn:x', 'DORMANT')
        assert a == b

    def test_state_change_voids_id(self):
        # DORMANT -> ACTIVE must produce a different ID so suppression auto-resurfaces
        dormant = compliance_app._make_finding_id('capability', 'role', 'arn:x', 'DORMANT')
        active = compliance_app._make_finding_id('capability', 'role', 'arn:x', 'ACTIVE')
        assert dormant != active

    def test_different_resources_differ(self):
        a = compliance_app._make_finding_id('capability', 'role', 'arn:x', 'DORMANT')
        b = compliance_app._make_finding_id('capability', 'role', 'arn:y', 'DORMANT')
        assert a != b


class TestExtractFindings:
    """_extract_findings should attach IDs across dimensions and return a flat list."""

    def test_attaches_ids_and_flattens(self):
        assessments = {
            'capability_level': {
                'risk_level': 'MEDIUM',
                'capability_level': 'ACTIONS_ENABLED',
                'actions_roles': [
                    {'role_name': 'r1', 'role_arn': 'arn:aws:iam::1:role/r1', 'status': 'DORMANT'},
                ],
            },
            'permission_scope': {
                'risk_level': 'HIGH',
                'high_risk_permissions': [
                    {'role': 'r1', 'action': 'iam:PassRole', 'resource_scope': '*', 'is_wildcard_resource': True},
                ],
                'moderate_risk_permissions': [],
            },
            'visibility_gaps': {
                'risk_level': 'MEDIUM',
                'private_connections': {'details': [
                    {'name': 'conn-1', 'status': 'ACTIVE', 'dns_resolution': 'IN_VPC', 'has_certificate': True},
                ]},
            },
        }
        findings = compliance_app._extract_findings(assessments)
        assert len(findings) == 3
        # IDs attached in place
        assert assessments['capability_level']['actions_roles'][0]['finding_id'].startswith('f-')
        assert assessments['permission_scope']['high_risk_permissions'][0]['finding_id'].startswith('f-')
        # flat list carries dimension + severity
        dims = {f['dimension'] for f in findings}
        assert dims == {'Capability', 'Permission', 'Visibility'}

    def test_empty_assessments_yield_no_findings(self):
        assert compliance_app._extract_findings({}) == []


class TestApplySuppressions:
    """Partition findings into active/suppressed/accepted; never delete."""

    def _findings(self):
        return [
            {'finding_id': 'f-a', 'dimension': 'Capability', 'severity': 'MEDIUM'},
            {'finding_id': 'f-b', 'dimension': 'Permission', 'severity': 'HIGH'},
            {'finding_id': 'f-c', 'dimension': 'Visibility', 'severity': 'MEDIUM'},
        ]

    def test_no_suppressions_all_active(self):
        out = compliance_app._apply_suppressions(self._findings(), {})
        assert out['active_count'] == 3
        assert out['suppressed_count'] == 0
        assert out['accepted_count'] == 0

    def test_suppress_and_accept_partition(self):
        supp = {
            'f-a': {'decision': 'suppress', 'reason': 'unused', 'added_by': 'x'},
            'f-b': {'decision': 'accept', 'reason': 'known', 'added_by': 'x'},
        }
        out = compliance_app._apply_suppressions(self._findings(), supp)
        assert out['active_count'] == 1  # only f-c remains active
        assert out['suppressed_count'] == 1
        assert out['accepted_count'] == 1
        assert out['accepted_high_count'] == 1  # f-b was HIGH
        # decision provenance annotated on the finding
        assert out['accepted'][0]['decision_reason'] == 'known'

    def test_stale_id_does_not_match(self):
        # A suppression for an id that no longer appears (state changed) is ignored
        supp = {'f-OLDSTATE': {'decision': 'suppress'}}
        out = compliance_app._apply_suppressions(self._findings(), supp)
        assert out['active_count'] == 3  # nothing suppressed — auto-resurfaced

