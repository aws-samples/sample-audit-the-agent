# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for Analyze function guardrails."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'analyze'))
import importlib.util
_spec = importlib.util.spec_from_file_location('analyze_app', os.path.join(os.path.dirname(__file__), '..', 'functions', 'analyze', 'app.py'))
analyze_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(analyze_app)

import pytest

class TestValidateRecommendations:
    def test_strips_organizational(self):
        recs = [{'priority': 'LOW', 'action': 'Consider consolidating spaces for efficiency', 'rationale': 'Overlapping personnel'}]
        assert len(analyze_app._validate_recommendations(recs, {})) == 0

    def test_strips_speculation(self):
        recs = [{'priority': 'MEDIUM', 'action': 'Lambda may be misconfigured based on frequency', 'rationale': 'Seems unnecessary'}]
        assert len(analyze_app._validate_recommendations(recs, {})) == 0

    def test_strips_normal_ops(self):
        recs = [{'priority': 'LOW', 'action': 'Establish baseline for ListAssociations frequency', 'rationale': '80 calls is high'}]
        assert len(analyze_app._validate_recommendations(recs, {})) == 0

    def test_strips_no_citation(self):
        recs = [{'priority': 'MEDIUM', 'action': 'Review agent configuration for improvements', 'rationale': 'General best practice'}]
        assert len(analyze_app._validate_recommendations(recs, {})) == 0

    def test_keeps_iam_recommendation(self):
        recs = [{'priority': 'HIGH', 'action': 'Scope ec2:TerminateInstances in 3 Actions roles to tagged resources', 'rationale': 'Broad * permission on 3 roles'}]
        result = analyze_app._validate_recommendations(recs, {})
        assert len(result) == 1

    def test_keeps_cost_recommendation(self):
        recs = [{'priority': 'HIGH', 'action': 'Credit burn at $850/day projects $7600 overage', 'rationale': 'Exhausts in 15 days'}]
        result = analyze_app._validate_recommendations(recs, {})
        assert len(result) == 1

    def test_caps_at_three(self):
        recs = [{'priority': 'HIGH', 'action': f'Scope ec2:Action{i} in {i} roles', 'rationale': f'{i} roles affected'} for i in range(1, 6)]
        assert len(analyze_app._validate_recommendations(recs, {})) == 3

    def test_empty_returns_empty(self):
        assert analyze_app._validate_recommendations([], {}) == []

class TestValidateRiskFlags:
    def test_strips_organizational(self):
        flags = [{'severity': 'LOW', 'flag': 'Team consolidation needed', 'detail': 'Consider reorganizing for efficiency', 'action': 'Merge'}]
        assert len(analyze_app._validate_risk_flags(flags)) == 0

    def test_strips_normal_ops(self):
        flags = [{'severity': 'LOW', 'flag': 'High polling', 'detail': 'ListAssociations called 80 times', 'action': 'Baseline'}]
        assert len(analyze_app._validate_risk_flags(flags)) == 0

    def test_keeps_legitimate(self):
        flags = [{'severity': 'HIGH', 'flag': 'Credit Exhaustion', 'detail': 'At $850/day burn rate credits exhaust', 'action': 'Review'}]
        assert len(analyze_app._validate_risk_flags(flags)) == 1

    def test_caps_at_five(self):
        flags = [{'severity': 'MEDIUM', 'flag': f'Issue {i}', 'detail': f'Detail {i}', 'action': f'Fix {i}'} for i in range(8)]
        assert len(analyze_app._validate_risk_flags(flags)) == 5
