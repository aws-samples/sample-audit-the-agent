import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'enrich'))
import importlib.util
_spec = importlib.util.spec_from_file_location('enrich_app', os.path.join(os.path.dirname(__file__), '..', 'functions', 'enrich', 'app.py'))
enrich_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(enrich_app)

import pytest
from datetime import datetime, timezone, timedelta

class TestBuildPartitionFilter:
    def test_single_month(self):
        end = datetime(2026, 8, 15, tzinfo=timezone.utc)
        result = enrich_app._build_partition_filter(end - timedelta(days=7), end, lookback_days=7)
        assert result == "(year = '2026' AND month = '08')"

    def test_two_months(self):
        end = datetime(2026, 8, 5, tzinfo=timezone.utc)
        result = enrich_app._build_partition_filter(end - timedelta(days=30), end, lookback_days=30)
        assert "month = '07'" in result and "month = '08'" in result and 'OR' in result

    def test_year_boundary(self):
        end = datetime(2026, 1, 5, tzinfo=timezone.utc)
        result = enrich_app._build_partition_filter(end - timedelta(days=30), end, lookback_days=30)
        assert "year = '2025'" in result and "year = '2026'" in result

class TestBuildCreditConsumption:
    """Test credit consumption using es_charge_from_cur parameter (avoids env var reload issues)."""

    def test_healthy(self, period_end):
        daily = [{'date': f'2026-08-0{d}', 'operation': 'POWER_CHAT', 'hours': 2, 'cost': 60.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(480.0, -480.0, [], daily, period_end, es_charge_from_cur=5000.0)
        assert result['alert_level'] == 'HEALTHY'
        assert result['monthly_credit_budget'] == 3750.0

    def test_on_pace_to_exceed(self, period_end):
        daily = [{'date': f'2026-08-0{d}', 'operation': 'POWER_CHAT', 'hours': 25, 'cost': 750.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(6000.0, -3750.0, [], daily, period_end, es_charge_from_cur=10000.0)
        assert result['alert_level'] == 'ON_PACE_TO_EXCEED'

    def test_exceeded(self, period_end):
        daily = [{'date': f'2026-08-0{d}', 'operation': 'POWER_CHAT', 'hours': 20, 'cost': 600.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(4800.0, -3750.0, [], daily, period_end, es_charge_from_cur=5000.0)
        assert result['alert_level'] == 'EXCEEDED'
        assert result['consumption_pct'] > 100

    def test_not_configured(self, period_end):
        result = enrich_app._build_credit_consumption(0, 0, [], [], period_end, es_charge_from_cur=0)
        assert result['alert_level'] == 'NOT_CONFIGURED'

    def test_cur_auto_detect_priority(self, period_end):
        daily = [{'date': f'2026-08-0{d}', 'operation': 'X', 'hours': 5, 'cost': 150.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(1200.0, -1200.0, [], daily, period_end, es_charge_from_cur=70000.0)
        assert result['monthly_credit_budget'] == 52500.0
        assert 'auto-detected' in result['budget_source']

    def test_burn_rate_math(self, period_end):
        daily = [{'date': f'2026-08-0{d}', 'operation': 'X', 'hours': 25, 'cost': 750.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(6000.0, -6000.0, [], daily, period_end, es_charge_from_cur=20000.0)
        assert result['burn_rate_per_day'] == 750.0
        assert result['credits_remaining'] == 9000.0
        assert result['days_until_exhaust'] == 12.0


class TestCreditStatus:
    """Credits are a monthly grant (75% of prior-month ES charge), reset month-end,
    no rollover — so 'infinite' days-until-exhaust is never valid. These cover the
    explicit credit_status states."""

    def test_not_configured(self, period_end):
        result = enrich_app._build_credit_consumption(0, 0, [], [], period_end, es_charge_from_cur=0)
        assert result['credit_status'] == 'NOT_CONFIGURED'
        assert result['days_until_exhaust'] is None

    def test_no_usage(self, period_end):
        # Budget configured, but zero spend this period -> NO_USAGE, never 'infinite'
        result = enrich_app._build_credit_consumption(0.0, 0.0, [], [], period_end, es_charge_from_cur=5000.0)
        assert result['credit_status'] == 'NO_USAGE'
        assert result['days_until_exhaust'] is None
        assert result['burn_rate_per_day'] == 0

    def test_exhausted(self, period_end):
        # mtd exceeds budget -> credits_remaining <= 0 -> EXHAUSTED (never shown as infinite)
        daily = [{'date': f'2026-08-0{d}', 'operation': 'X', 'hours': 20, 'cost': 600.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(4800.0, -3750.0, [], daily, period_end, es_charge_from_cur=5000.0)
        assert result['credit_status'] == 'EXHAUSTED'
        assert result['days_until_exhaust'] == 0

    def test_sufficient_through_month_end(self, period_end):
        # Low burn that outlasts the ~23 days remaining -> SUFFICIENT, no countdown
        daily = [{'date': f'2026-08-0{d}', 'operation': 'X', 'hours': 1, 'cost': 30.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(240.0, -240.0, [], daily, period_end, es_charge_from_cur=5000.0)
        assert result['credit_status'] == 'SUFFICIENT'
        assert result['days_until_exhaust'] is None
        assert result['days_remaining_in_month'] == 23

    def test_will_exhaust_before_month_end(self, period_end):
        # High burn that runs out before the monthly reset -> WILL_EXHAUST with a real countdown
        daily = [{'date': f'2026-08-0{d}', 'operation': 'X', 'hours': 25, 'cost': 750.0} for d in range(1, 9)]
        result = enrich_app._build_credit_consumption(6000.0, -6000.0, [], daily, period_end, es_charge_from_cur=20000.0)
        assert result['credit_status'] == 'WILL_EXHAUST'
        assert result['days_until_exhaust'] == 12.0
        # countdown must be shorter than days left in month, else it'd be SUFFICIENT
        assert result['days_until_exhaust'] < result['days_remaining_in_month']

    def test_summary_never_contains_infinity(self, period_end):
        for es in (0, 5000.0, 20000.0):
            daily = [{'date': f'2026-08-0{d}', 'operation': 'X', 'hours': 25, 'cost': 750.0} for d in range(1, 9)]
            result = enrich_app._build_credit_consumption(6000.0, -6000.0, [], daily, period_end, es_charge_from_cur=es)
            assert '∞' not in result['summary']
