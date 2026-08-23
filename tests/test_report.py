import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'report'))
import importlib.util
_spec = importlib.util.spec_from_file_location('report_app', os.path.join(os.path.dirname(__file__), '..', 'functions', 'report', 'app.py'))
report_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report_app)

import pytest
from unittest.mock import patch, MagicMock

class TestFmtDaysUntilExhaust:
    """The report must never render 'infinite' days — credits reset monthly with
    no rollover. Covers both the full and compact formatters + the legacy
    0-days inversion bug (0 was wrongly shown as ∞ via `or "∞"`)."""

    def test_exhausted_not_infinite(self):
        c = {'credit_status': 'EXHAUSTED', 'days_until_exhaust': 0}
        assert report_app._fmt_days_until_exhaust(c) == 'Exhausted'
        assert report_app._fmt_days_until_exhaust_compact(c) == 'Exhausted'

    def test_no_usage(self):
        c = {'credit_status': 'NO_USAGE', 'days_until_exhaust': None}
        assert report_app._fmt_days_until_exhaust(c) == 'No usage this period'

    def test_not_configured(self):
        c = {'credit_status': 'NOT_CONFIGURED', 'days_until_exhaust': None}
        assert report_app._fmt_days_until_exhaust(c) == 'N/A'

    def test_sufficient_shows_days_left(self):
        c = {'credit_status': 'SUFFICIENT', 'days_until_exhaust': None, 'days_remaining_in_month': 23}
        assert report_app._fmt_days_until_exhaust(c) == 'Sufficient through month-end (23 days left)'
        assert report_app._fmt_days_until_exhaust_compact(c) == 'OK'

    def test_will_exhaust_shows_countdown(self):
        c = {'credit_status': 'WILL_EXHAUST', 'days_until_exhaust': 6}
        assert report_app._fmt_days_until_exhaust(c) == '6 days'
        assert report_app._fmt_days_until_exhaust_compact(c) == '6 days'

    def test_no_infinity_symbol_ever(self):
        for c in [
            {'credit_status': 'EXHAUSTED', 'days_until_exhaust': 0},
            {'credit_status': 'NO_USAGE', 'days_until_exhaust': None},
            {'credit_status': 'SUFFICIENT', 'days_until_exhaust': None, 'days_remaining_in_month': 10},
            {'credit_status': 'WILL_EXHAUST', 'days_until_exhaust': 3},
            {},  # empty / legacy
        ]:
            assert '∞' not in report_app._fmt_days_until_exhaust(c)
            assert '∞' not in report_app._fmt_days_until_exhaust_compact(c)

    def test_legacy_zero_is_exhausted_not_infinite(self):
        # Backward-compat: old payload with days_until_exhaust=0 and no credit_status
        # must render 'Exhausted', not '∞' (the original inversion bug).
        c = {'days_until_exhaust': 0}
        assert report_app._fmt_days_until_exhaust(c) == 'Exhausted'

    def test_legacy_none_is_na(self):
        assert report_app._fmt_days_until_exhaust({'days_until_exhaust': None}) == 'N/A'

class TestGetScopeLabel:
    def test_returns_string(self):
        result = report_app._get_scope_label()
        assert isinstance(result, str)
        assert 'Agent' in result

class TestShortenUrl:
    def test_success(self):
        with patch('urllib.request.urlopen') as m:
            resp = MagicMock(); resp.read.return_value = b'https://tinyurl.com/abc'; resp.__enter__ = lambda s: s; resp.__exit__ = MagicMock(return_value=False)
            m.return_value = resp
            assert report_app._shorten_url('https://long.url') == 'https://tinyurl.com/abc'

    def test_fallback(self):
        with patch('urllib.request.urlopen', side_effect=Exception('fail')):
            assert report_app._shorten_url('https://original.url') == 'https://original.url'

class TestBuildHtml:
    def _inputs(self):
        analysis = {'executive_summary': 'Test summary.', 'risk_level': 'GREEN', 'risk_flags': [], 'authorization_chain': [], 'recommendations': []}
        trust = {'trust_posture': {'overall_risk': 'LOW'}, 'assessments': {k: {'risk_level': 'LOW', 'summary': 'OK.'} for k in ['capability_level', 'permission_scope', 'visibility_gaps', 'integration_exposure', 'human_approval']}}
        credits = {'alert_level': 'HEALTHY', 'monthly_credit_budget': 3750, 'mtd_usage': 500, 'consumption_pct': 13.3, 'burn_rate_per_day': 62, 'projected_month_total': 1937, 'credits_remaining': 3250, 'days_until_exhaust': 52, 'summary': 'Healthy.'}
        collect = {'total_events': 50, 'tasks': [{'triggered_at': '2026-08-08T10:00', 'triggered_by': 'user', 'task_type': 'INVESTIGATION', 'trigger_type': 'human-console', 'agent_space_id': 'd33850ed', 'status': 'COMPLETED'}], 'trigger_summary': {'human-console': 1}, 'events': []}
        return analysis, trust, credits, collect

    def test_contains_doctype(self):
        assert '<!DOCTYPE html>' in report_app._build_html('test', *self._inputs())

    def test_contains_scope(self):
        assert 'Scope:' in report_app._build_html('test', *self._inputs())

    def test_contains_summary(self):
        assert 'Test summary.' in report_app._build_html('test', *self._inputs())

    def test_contains_trust_posture(self):
        assert 'Trust Posture' in report_app._build_html('test', *self._inputs())

    def test_contains_pagination(self):
        assert 'paginateTasks' in report_app._build_html('test', *self._inputs())

    def test_xss_prevention(self):
        a, t, c, co = self._inputs()
        a['executive_summary'] = '<script>alert("xss")</script>'
        html = report_app._build_html('test', a, t, c, co)
        assert '<script>alert' not in html

    def test_ai_disclaimer(self):
        a, t, c, co = self._inputs()
        a['risk_flags'] = [{'severity': 'MEDIUM', 'flag': 'Test', 'detail': 'Test', 'action': 'Act'}]
        assert 'review with caution' in report_app._build_html('test', a, t, c, co)


class TestFindingsCsv:
    """findings.csv is the CISO's suppress/accept interface — must round-trip cleanly."""

    def test_header_and_blank_decision_columns(self):
        findings = [
            {'finding_id': 'f-abc123', 'dimension': 'Capability',
             'finding': 'role x (DORMANT)', 'severity': 'MEDIUM'},
        ]
        csv_text = report_app._build_findings_csv(findings)
        lines = csv_text.strip().split('\n')
        assert lines[0].strip() == 'finding_id,dimension,finding,severity,decision,reason'
        assert 'f-abc123' in lines[1]
        # decision and reason columns present but blank for the CISO to fill
        assert lines[1].rstrip().endswith(',,')

    def test_empty_findings_yields_header_only(self):
        csv_text = report_app._build_findings_csv([])
        assert csv_text.strip() == 'finding_id,dimension,finding,severity,decision,reason'

    def test_commas_in_finding_are_quoted(self):
        findings = [{'finding_id': 'f-1', 'dimension': 'Permission',
                     'finding': 'role allows a, b, c', 'severity': 'HIGH'}]
        csv_text = report_app._build_findings_csv(findings)
        assert '"role allows a, b, c"' in csv_text


class TestSuppressedSection:
    """Suppressed/accepted findings render in a collapsed, audit-complete section."""

    def test_empty_when_no_decisions(self):
        assert report_app._build_suppressed_section({}) == ''

    def test_renders_accepted_and_suppressed(self):
        trust = {
            'accepted_findings': [
                {'finding_id': 'f-b', 'dimension': 'Permission', 'finding': 'x allows y',
                 'decision_reason': 'known risk', 'decision_by': 'ciso-reviewer'},
            ],
            'suppressed_findings': [
                {'finding_id': 'f-a', 'dimension': 'Capability', 'finding': 'role z',
                 'decision_reason': 'unused', 'decision_by': 'ciso-reviewer'},
            ],
        }
        html = report_app._build_suppressed_section(trust)
        assert 'Suppressed &amp; Accepted' in html
        assert 'f-a' in html and 'f-b' in html
        assert 'known risk' in html and 'unused' in html
        assert 'ACCEPT' in html and 'SUPPRESS' in html


class TestSpaceCostSection:
    """Consolidated Agent Space Cost Breakdown — surfaces per-space cost that was
    captured by enrich but previously never rendered."""

    def _cur_cost(self):
        return {
            'devops': {
                'agent_display_name': 'DevOps Agent', 'source': 'CUR',
                'by_space_named': {
                    'Production Monitoring': {'uuid': 'd33850ed', 'account_id': '111111111111',
                                              'total_hours': 15.1, 'gross_cost': 453.0, 'net_cost': 113.25,
                                              'tags': {'application': 'payments', 'environment': 'prod',
                                                       'aws:createdBy': 'should-be-hidden'}},
                    'CI Pipeline': {'uuid': 'a17c2f90', 'account_id': '111111111111',
                                    'total_hours': 6.2, 'gross_cost': 187.0, 'net_cost': 46.75, 'tags': {}},
                },
            },
            'security': {
                'agent_display_name': 'Security Agent', 'source': 'CUR',
                'by_space_named': {
                    'SecOps Review': {'uuid': 'b92c1f04', 'account_id': '111111111111',
                                      'total_hours': 5.7, 'gross_cost': 172.0, 'net_cost': 43.0,
                                      'tags': {'oncall-team': 'sre-security'}},
                },
            },
        }

    def test_consolidates_across_agents(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        assert 'Production Monitoring' in html
        assert 'CI Pipeline' in html
        assert 'SecOps Review' in html
        # Agent Type column values present for both agents
        assert 'DevOps Agent' in html and 'Security Agent' in html

    def test_header_count(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        assert 'Agent Space Cost Breakdown (3)' in html

    def test_sorted_by_gross_cost_desc(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        # Highest gross (453 Production Monitoring) must appear before lowest (172 SecOps Review)
        assert html.index('Production Monitoring') < html.index('SecOps Review')

    def test_tags_rendered_as_key_value(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        # Purpose tags surfaced as key=value pairs
        assert 'application=payments' in html
        assert 'environment=prod' in html
        assert 'oncall-team=sre-security' in html

    def test_aws_reserved_tags_excluded(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        # aws:* tags must not appear
        assert 'aws:createdBy' not in html
        assert 'should-be-hidden' not in html

    def test_untagged_space_shows_dash(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        # CI Pipeline has no tags → em-dash placeholder present in the table
        assert '—' in html

    def test_tags_column_header(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        assert '<th>Tags</th>' in html
        assert 'Owner' not in html

    def test_columns_are_usage_cost_and_pct_budget_not_gross_net(self):
        html = report_app._build_space_cost_section(self._cur_cost())
        assert '<th class="num">Usage Cost</th>' in html
        assert '<th class="num">% of Credit Budget</th>' in html
        # Old gross/net column headers must be gone
        assert '<th class="num">Gross</th>' not in html
        assert '<th class="num">Net</th>' not in html

    def test_devops_shows_pct_of_credit_budget(self):
        # With a $10,000 budget, a $453 devops space = 4.5%
        credits = {'monthly_credit_budget': 10000}
        html = report_app._build_space_cost_section(self._cur_cost(), credits)
        assert '4.5%' in html  # 453 / 10000

    def test_security_shows_na_for_credit_budget(self):
        credits = {'monthly_credit_budget': 10000}
        html = report_app._build_space_cost_section(self._cur_cost(), credits)
        # Security Agent has no credit pool → N/A
        assert 'N/A' in html

    def test_devops_no_budget_shows_dash_not_na(self):
        # DevOps but no configured budget → em-dash (not N/A, which is security-only)
        html = report_app._build_space_cost_section(self._cur_cost(), {'monthly_credit_budget': 0})
        assert 'N/A' in html  # security still N/A

    def test_ce_fallback_shows_cur_guidance(self):
        # Cost Explorer path has no by_space → guidance note, not an empty table
        ce = {'devops': {'agent_display_name': 'DevOps Agent', 'source': 'cost_explorer', 'summary': {}}}
        html = report_app._build_space_cost_section(ce)
        assert 'requires the CUR' in html

    def test_empty_input(self):
        html = report_app._build_space_cost_section({})
        assert 'Agent Space Cost Breakdown' in html

    def test_raw_by_space_uuid_fallback(self):
        # When only raw (unnamed) by_space is present, UUIDs are shortened for display
        cost = {'devops': {'agent_display_name': 'DevOps Agent', 'source': 'CUR',
                           'by_space': {'d33850edaaaa': {'account_id': '1', 'total_hours': 1, 'gross_cost': 5.0, 'net_cost': 1.0}}}}
        html = report_app._build_space_cost_section(cost)
        assert 'space-d33850ed' in html
