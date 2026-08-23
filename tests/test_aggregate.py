# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the aggregate function's agent-space name resolution.

Covers:
- API-based name resolution (devops-agent ListAgentSpaces -> {uuid: name}),
  mocked so no real AWS call is made.
- Fail-open to a truncated-UUID label when the API is unavailable.
- The nested per-agent cost structure (cost[agent]['by_space']) getting a
  by_space_named copy — regression coverage for the bug where _resolve_space_names
  previously looked only at the top-level cost['by_space'] (which never existed).
"""

import os
import importlib.util

import pytest

FUNCTIONS_DIR = os.path.join(os.path.dirname(__file__), '..', 'functions')


def _load_module(name, rel_path):
    module_path = os.path.join(FUNCTIONS_DIR, *rel_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def space_names(monkeypatch):
    """Load space_names with a pre-seeded API name cache (no real boto3 call)."""
    mod = _load_module('space_names', ['aggregate', 'space_names.py'])
    # Seed the cache so _get_api_space_names() short-circuits (no AWS call).
    monkeypatch.setattr(mod, '_API_NAME_MAP', {
        'd33850ed': 'Production Monitoring',
        '498a79ac': 'Application Health',
        'b92c1f04': 'Incident Response',
    })
    return mod


@pytest.fixture
def aggregate_app(space_names, monkeypatch):
    """Load aggregate app and point its resolver at the seeded space_names."""
    mod = _load_module('aggregate_app', ['aggregate', 'app.py'])
    # aggregate does `from space_names import resolve_space_name` — rebind it to
    # the seeded module's resolver so tests use the mocked API map.
    monkeypatch.setattr(mod, 'resolve_space_name', space_names.resolve_space_name)
    return mod


class TestResolveSpaceNameAPI:
    """resolve_space_name resolves via the (mocked) API map, else UUID fallback."""

    def test_known_uuid_resolves_from_api(self, space_names):
        assert space_names.resolve_space_name('d33850ed') == 'Production Monitoring'

    def test_unknown_uuid_falls_back_to_short_uuid(self, space_names):
        assert space_names.resolve_space_name('unknown12345') == 'space-unknown1'

    def test_api_unavailable_fails_open(self, monkeypatch):
        """If ListAgentSpaces errors, resolution falls back to UUID labels."""
        mod = _load_module('space_names_fail', ['aggregate', 'space_names.py'])

        class _BoomClient:
            def list_agent_spaces(self, **kwargs):
                raise RuntimeError('API not available')

        monkeypatch.setattr(mod.boto3, 'client', lambda *a, **k: _BoomClient())
        # Cache starts as None → triggers the (failing) fetch → empty map → fallback.
        assert mod.resolve_space_name('d33850ed') == 'space-d33850ed'

    def test_api_map_built_from_list_response(self, monkeypatch):
        mod = _load_module('space_names_ok', ['aggregate', 'space_names.py'])

        class _OkClient:
            def list_agent_spaces(self, **kwargs):
                return {'agentSpaces': [
                    {'agentSpaceId': 'aaa', 'name': 'Alpha'},
                    {'agentSpaceId': 'bbb', 'name': 'Beta'},
                ]}

        monkeypatch.setattr(mod.boto3, 'client', lambda *a, **k: _OkClient())
        assert mod.resolve_space_name('aaa') == 'Alpha'
        assert mod.resolve_space_name('bbb') == 'Beta'


class TestGetSpaceTags:
    """get_space_tags returns user tags from get_agent_space; aws:* excluded; fail-open."""

    def test_returns_user_tags(self, monkeypatch):
        mod = _load_module('space_names_tags', ['aggregate', 'space_names.py'])

        class _Client:
            def get_agent_space(self, agentSpaceId=None):
                return {'agentSpace': {'agentSpaceId': agentSpaceId, 'name': 'X',
                                       'tags': {'application': 'payments', 'environment': 'prod'}}}

        monkeypatch.setattr(mod.boto3, 'client', lambda *a, **k: _Client())
        tags = mod.get_space_tags('space-1')
        assert tags == {'application': 'payments', 'environment': 'prod'}

    def test_excludes_aws_reserved_tags(self, monkeypatch):
        mod = _load_module('space_names_tags2', ['aggregate', 'space_names.py'])

        class _Client:
            def get_agent_space(self, agentSpaceId=None):
                return {'agentSpace': {'tags': {'application': 'payments',
                                                'aws:createdBy': 'x', 'AWS:cost': 'y'}}}

        monkeypatch.setattr(mod.boto3, 'client', lambda *a, **k: _Client())
        tags = mod.get_space_tags('space-2')
        assert tags == {'application': 'payments'}

    def test_fails_open_to_empty(self, monkeypatch):
        mod = _load_module('space_names_tags3', ['aggregate', 'space_names.py'])

        class _Boom:
            def get_agent_space(self, agentSpaceId=None):
                raise RuntimeError('no API')

        monkeypatch.setattr(mod.boto3, 'client', lambda *a, **k: _Boom())
        assert mod.get_space_tags('space-3') == {}


class TestResolveSpaceNamesNested:
    """The per-agent (nested) cost structure must get by_space_named."""

    def _record(self):
        return {
            'cost': {
                'devops': {
                    'source': 'CUR',
                    'by_space': {
                        'd33850ed': {'account_id': '111111111111', 'gross_cost': 453.0},
                        'unknown12': {'account_id': '111111111111', 'gross_cost': 187.0},
                    },
                },
                'security': {
                    'source': 'CUR',
                    'by_space': {
                        'b92c1f04': {'account_id': '111111111111', 'gross_cost': 172.0},
                    },
                },
            },
            'activity': {},
            'tasks': {},
        }

    def test_named_added_per_agent(self, aggregate_app):
        rec = self._record()
        aggregate_app._resolve_space_names(rec)
        assert 'by_space_named' in rec['cost']['devops']
        assert 'by_space_named' in rec['cost']['security']

    def test_known_uuid_resolves_to_friendly_name(self, aggregate_app):
        rec = self._record()
        aggregate_app._resolve_space_names(rec)
        named = rec['cost']['devops']['by_space_named']
        assert 'Production Monitoring' in named
        assert named['Production Monitoring']['uuid'] == 'd33850ed'
        assert named['Production Monitoring']['gross_cost'] == 453.0

    def test_unknown_uuid_falls_back(self, aggregate_app):
        rec = self._record()
        aggregate_app._resolve_space_names(rec)
        named = rec['cost']['devops']['by_space_named']
        assert 'space-unknown1' in named

    def test_raw_by_space_preserved(self, aggregate_app):
        rec = self._record()
        aggregate_app._resolve_space_names(rec)
        assert 'd33850ed' in rec['cost']['devops']['by_space']


class TestResolveSpaceNamesEdgeCases:
    def test_no_cost_section_is_noop(self, aggregate_app):
        rec = {'activity': {}, 'tasks': {}}
        aggregate_app._resolve_space_names(rec)  # must not raise
        assert 'cost' not in rec

    def test_agent_without_by_space_skipped(self, aggregate_app):
        rec = {'cost': {'devops': {'source': 'cost_explorer'}}, 'activity': {}, 'tasks': {}}
        aggregate_app._resolve_space_names(rec)
        assert 'by_space_named' not in rec['cost']['devops']

    def test_legacy_flat_by_space(self, aggregate_app):
        # Backward compat: a flat top-level cost['by_space'] still resolves.
        rec = {'cost': {'by_space': {'d33850ed': {'gross_cost': 10.0}}}, 'activity': {}, 'tasks': {}}
        aggregate_app._resolve_space_names(rec)
        assert 'by_space_named' in rec['cost']
        assert 'Production Monitoring' in rec['cost']['by_space_named']
