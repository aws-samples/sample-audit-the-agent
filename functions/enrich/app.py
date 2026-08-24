# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Enrich Lambda — retrieves agent cost from CUR (Cost and Usage Reports) via Athena.

CUR is the billing system of record. It provides:
- Per-agent-space cost breakdown (line_item_resource_id = agentspace ARN)
- Per-operation type (POWER_CHAT, TRIAGE, EVALUATION)
- Per-account attribution (line_item_usage_account_id)
- Hourly granularity (line_item_usage_start_date)
- Gross cost + EDP discounts + ES credits (separate line items)

Pricing: $30/hour ($0.50/min, $0.0083/sec) for all operation types.
Credits: Enterprise Support customers get 75% of ES charges as DevOps Agent credits.

Data flow: CUR → S3 (Parquet) → Athena query → cost summary for report.
Fallback: Cost Explorer API when CUR/Athena is not configured.
"""

import json
import logging
import os
import time
import boto3
from datetime import datetime, timezone, timedelta
from agent_config import get_active_agents

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get('REGION', 'us-east-1')
CUR_DATABASE = os.environ.get('CUR_DATABASE', '')
CUR_TABLE = os.environ.get('CUR_TABLE', '')
ATHENA_OUTPUT_BUCKET = os.environ.get('ATHENA_OUTPUT_BUCKET', '')
ATHENA_WORKGROUP = os.environ.get('ATHENA_WORKGROUP', 'primary')
MONTHLY_ES_CHARGE = float(os.environ.get('MONTHLY_ES_CHARGE', '0'))
CUR_CROSS_ACCOUNT_ROLE_ARN = os.environ.get('CUR_CROSS_ACCOUNT_ROLE_ARN', '')


def _get_athena_client():
    """Get Athena client — uses cross-account role if configured.

    For enterprise deployments where CUR lives in the payer/management account
    and AgentAudit runs in a linked account, this assumes a role in the CUR
    account to execute Athena queries.

    Returns:
        Boto3 Athena client (same-account or cross-account).
    """
    if CUR_CROSS_ACCOUNT_ROLE_ARN:
        logger.info("Assuming cross-account role for CUR access: %s", CUR_CROSS_ACCOUNT_ROLE_ARN)
        sts = boto3.client('sts', region_name=REGION)
        creds = sts.assume_role(
            RoleArn=CUR_CROSS_ACCOUNT_ROLE_ARN,
            RoleSessionName='AgentAudit-Enrich',
            DurationSeconds=900,
        )['Credentials']
        return boto3.client(
            'athena',
            region_name=REGION,
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
        )
    return boto3.client('athena', region_name=REGION)


def _query_athena(athena_client: object, query: str) -> list:
    """Execute an Athena query and return results as list of dicts."""
    output_location = f"s3://{ATHENA_OUTPUT_BUCKET}/agentaudit-queries/"

    start_resp = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': CUR_DATABASE},
        WorkGroup=ATHENA_WORKGROUP,
        ResultConfiguration={'OutputLocation': output_location},
    )
    query_id = start_resp['QueryExecutionId']

    # Poll for completion (max 60 seconds)
    for _ in range(30):
        status_resp = athena_client.get_query_execution(QueryExecutionId=query_id)
        state = status_resp['QueryExecution']['Status']['State']
        if state in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
            break
        time.sleep(2)

    if state != 'SUCCEEDED':
        reason = status_resp['QueryExecution']['Status'].get('StateChangeReason', 'unknown')
        logger.error("Athena query failed: state=%s reason=%s", state, reason)
        return []

    # Fetch results
    results = []
    paginator = athena_client.get_paginator('get_query_results')
    columns = []

    for page in paginator.paginate(QueryExecutionId=query_id):
        rows = page['ResultSet']['Rows']
        if not columns:
            columns = [col['VarCharValue'] for col in rows[0]['Data']]
            rows = rows[1:]  # Skip header row

        for row in rows:
            values = [col.get('VarCharValue', '') for col in row['Data']]
            results.append(dict(zip(columns, values)))

    return results


def _build_partition_filter(period_start: datetime, period_end: datetime, lookback_days: int = 30) -> str:
    """Build a CUR partition filter clause using year/month partition keys.

    CUR tables are partitioned by `year` and `month` columns. This function
    generates the appropriate WHERE clause to cover the reporting window,
    handling month boundaries (e.g., querying Jul 28 - Aug 8 spans two partitions).

    Args:
        period_start: Start of the reporting period.
        period_end: End of the reporting period.
        lookback_days: Number of days to look back for cost data (default: 30).

    Returns:
        SQL WHERE clause fragment (e.g., "(year = '2026' AND month = '07') OR (year = '2026' AND month = '08')").
    """
    # Determine which year/month partitions we need
    lookback_start = period_end - timedelta(days=lookback_days)
    partitions = set()

    current = lookback_start
    while current <= period_end:
        partitions.add((current.strftime('%Y'), current.strftime('%m')))
        current += timedelta(days=1)

    if len(partitions) == 1:
        year, month = partitions.pop()
        return f"(year = '{year}' AND month = '{month}')"
    else:
        clauses = [f"(year = '{y}' AND month = '{m}')" for y, m in sorted(partitions)]
        return f"({' OR '.join(clauses)})"


def _get_es_charge_from_cur(athena_client: object, period_end: datetime) -> float:
    """Query CUR for previous month's Enterprise Support charge.

    The ES credit budget for the current month is 75% of the previous month's
    ES charge. This function queries CUR directly — no hardcoded parameter needed.

    Args:
        athena_client: Boto3 Athena client.
        period_end: Current reporting period end (used to determine "previous month").

    Returns:
        Previous month's ES charge amount, or 0 if not found.
    """
    # Previous month
    first_of_current = period_end.replace(day=1)
    prev_month_end = first_of_current - timedelta(days=1)
    prev_year = prev_month_end.strftime('%Y')
    prev_month = prev_month_end.strftime('%m')

    query = f"""
    SELECT SUM(line_item_unblended_cost) AS es_charge
    FROM {CUR_TABLE}
    WHERE line_item_product_code = 'AWSSupportEnterprise'
        AND line_item_line_item_type IN ('Usage', 'EdpDiscount')
        AND year = '{prev_year}'
        AND month = '{prev_month}'
    """

    try:
        results = _query_athena(athena_client, query)
        if results and results[0].get('es_charge'):
            charge = float(results[0]['es_charge'])
            logger.info("ES charge from CUR (prev month %s-%s): $%.2f", prev_year, prev_month, charge)
            return charge
    except Exception as exc:
        logger.warning("Failed to query ES charge from CUR: %s", exc)

    return 0


def _build_credit_consumption(
    total_gross: float,
    total_credits: float,
    credit_details: list,
    daily_trend: list,
    period_end: datetime,
    es_charge_from_cur: float = 0,
) -> dict:
    """Build credit consumption analysis for ES customers.

    Enterprise Support customers get 75% of their monthly ES charge as agent
    credits. This function calculates burn rate, projection, and days until
    exhaustion — the metrics leadership actually cares about (not "$0 net cost").

    Credit budget source priority:
    1. CUR query (previous month ES charge) — auto-detected, most accurate
    2. MONTHLY_ES_CHARGE parameter — customer-provided fallback
    3. Neither — report shows "not configured"

    Args:
        total_gross: Gross usage cost this month (before credits).
        total_credits: Total credits applied (negative value from CUR).
        credit_details: Breakdown of credit line items.
        daily_trend: Daily cost breakdown from CUR.
        period_end: End of the reporting period (for day-of-month calculation).
        es_charge_from_cur: ES charge auto-detected from CUR (0 if not found).

    Returns:
        Dict with credit budget, consumption, burn rate, projection, and alert level.
    """
    import calendar

    # Determine ES charge: prefer CUR auto-detection, fall back to parameter
    if es_charge_from_cur > 0:
        es_charge = es_charge_from_cur
        budget_source = 'auto-detected from ES billing'
    elif MONTHLY_ES_CHARGE > 0:
        es_charge = MONTHLY_ES_CHARGE
        budget_source = 'based on Enterprise Support charge'
    else:
        es_charge = 0
        budget_source = 'not configured'

    monthly_credit_budget = round(es_charge * 0.75, 2) if es_charge else 0
    day_of_month = period_end.day
    days_in_month = calendar.monthrange(period_end.year, period_end.month)[1]
    days_remaining = days_in_month - day_of_month

    # Calculate MTD usage from daily trend (sum all days in current month)
    current_month = period_end.strftime('%Y-%m')
    mtd_cost = sum(
        d['cost'] for d in daily_trend
        if d.get('date', '').startswith(current_month)
    )

    # If no daily trend data, use total_gross as MTD approximation
    if mtd_cost == 0:
        mtd_cost = total_gross

    # Burn rate (average daily spend)
    burn_rate = round(mtd_cost / max(day_of_month, 1), 2)

    # Projection for full month
    projected_month_total = round(burn_rate * days_in_month, 2)

    # Credits remaining
    credits_remaining = round(monthly_credit_budget - mtd_cost, 2)

    # Days until exhaustion at current burn rate.
    # Credits are a monthly grant (75% of prior-month ES charge), reset at
    # month-end with no rollover. Exhaustion is therefore bounded by the days
    # remaining in the month — "infinite" is never a valid outcome. credit_status
    # captures the real state; days_until_exhaust is only a countdown when credits
    # will actually run out before the monthly reset.
    if monthly_credit_budget <= 0:
        credit_status = 'NOT_CONFIGURED'
        days_until_exhaust = None
    elif credits_remaining <= 0:
        credit_status = 'EXHAUSTED'
        days_until_exhaust = 0
    elif burn_rate <= 0:
        credit_status = 'NO_USAGE'  # no spend yet this period
        days_until_exhaust = None
    else:
        raw_days = credits_remaining / burn_rate
        if raw_days >= days_remaining:
            credit_status = 'SUFFICIENT'  # credits outlast the monthly reset
            days_until_exhaust = None
        else:
            credit_status = 'WILL_EXHAUST'  # runs out before month-end
            days_until_exhaust = round(raw_days, 1)

    # Consumption percentage
    consumption_pct = round((mtd_cost / monthly_credit_budget) * 100, 1) if monthly_credit_budget > 0 else 0

    # Alert level based on consumption pace
    # If usage pace would exceed budget by month end, flag it
    if monthly_credit_budget <= 0:
        alert_level = 'NOT_CONFIGURED'
    elif consumption_pct > 100:
        alert_level = 'EXCEEDED'
    elif projected_month_total > monthly_credit_budget:
        alert_level = 'ON_PACE_TO_EXCEED'
    elif consumption_pct > (day_of_month / days_in_month) * 100 * 1.2:
        # Consuming faster than proportional (20% buffer)
        alert_level = 'ELEVATED'
    else:
        alert_level = 'HEALTHY'

    return {
        'monthly_es_charge': es_charge,
        'monthly_credit_budget': monthly_credit_budget,
        'budget_source': budget_source,
        'mtd_usage': round(mtd_cost, 2),
        'consumption_pct': consumption_pct,
        'burn_rate_per_day': burn_rate,
        'projected_month_total': projected_month_total,
        'credits_remaining': max(credits_remaining, 0),
        'days_until_exhaust': days_until_exhaust,
        'credit_status': credit_status,
        'days_remaining_in_month': days_remaining,
        'alert_level': alert_level,
        'total_credits_applied': round(total_credits, 2),
        'credit_line_items': credit_details,
        'summary': _credit_summary_text(
            alert_level, monthly_credit_budget, mtd_cost, consumption_pct,
            burn_rate, projected_month_total, days_until_exhaust, days_remaining,
        ),
    }


def _credit_summary_text(
    alert_level: str, budget: float, mtd: float, pct: float,
    burn_rate: float, projected: float, days_exhaust: float, days_remaining: int,
) -> str:
    """Generate human-readable credit consumption summary.

    Args:
        alert_level: HEALTHY, ELEVATED, ON_PACE_TO_EXCEED, EXCEEDED, NOT_CONFIGURED.
        budget: Monthly credit budget.
        mtd: Month-to-date usage.
        pct: Consumption percentage.
        burn_rate: Average daily spend.
        projected: Projected month-end total.
        days_exhaust: Days until credits exhausted.
        days_remaining: Days left in month.

    Returns:
        One-line summary string for the report.
    """
    if alert_level == 'NOT_CONFIGURED':
        return 'Credit budget not configured — set MONTHLY_ES_CHARGE parameter to enable tracking.'
    elif alert_level == 'EXCEEDED':
        overage = round(mtd - budget, 2)
        return f'⚠️ CREDITS EXCEEDED — ${overage:,.2f} over budget. MTD usage ${mtd:,.2f} vs ${budget:,.2f} budget ({pct:.0f}% consumed).'
    elif alert_level == 'ON_PACE_TO_EXCEED':
        overage = round(projected - budget, 2)
        exhaust_txt = (
            f'Credits exhaust in ~{days_exhaust:.0f} days'
            if isinstance(days_exhaust, (int, float))
            else 'Credits expected to last through month-end'
        )
        return f'⚠️ ON PACE TO EXCEED — at ${burn_rate:,.2f}/day, projected ${projected:,.2f} vs ${budget:,.2f} budget. {exhaust_txt} ({days_remaining} days left in month).'
    elif alert_level == 'ELEVATED':
        return f'📈 ELEVATED — ${mtd:,.2f} used ({pct:.0f}% of ${budget:,.2f} budget). Burn rate ${burn_rate:,.2f}/day is above proportional pace.'
    else:
        if burn_rate == 0 and mtd == 0:
            return f'✅ NO ACTIVITY — $0 consumed against ${budget:,.0f} credit budget. No usage detected this period.'
        return f'✅ HEALTHY — ${mtd:,.2f} used ({pct:.0f}% of ${budget:,.2f} budget). At ${burn_rate:,.2f}/day, credits sufficient for remaining {days_remaining} days.'


def _enrich_via_cur(athena_client: object, period_start: datetime, period_end: datetime, product_code: str = 'DevOpsAgent', include_credits: bool = True) -> dict:
    """Query CUR via Athena for DevOps Agent cost data.

    Uses partition keys (year, month) to efficiently query the CUR table.
    The table name is customer-provided (not a standard convention).
    Supports lookback windows spanning multiple months.

    Args:
        athena_client: Boto3 Athena client.
        period_start: Start of the reporting period.
        period_end: End of the reporting period.
        product_code: CUR line_item_product_code to filter (e.g. 'DevOpsAgent', 'SecAgent').
        include_credits: Whether to calculate credit consumption (only for DevOps Agent).

    Returns:
        Dict with per-space cost breakdown, credits, and daily trend.
    """
    # Build partition filter — handle month boundaries
    partitions = _build_partition_filter(period_start, period_end)

    logger.info("Querying CUR (table=%s, partitions=%s)", CUR_TABLE, partitions)

    # --- Query 1: Per-space, per-operation cost breakdown ---
    space_query = f"""SELECT
        line_item_resource_id,
        line_item_operation,
        line_item_usage_account_id,
        line_item_usage_type,
        SUM(line_item_usage_amount) AS total_hours,
        SUM(line_item_unblended_cost) AS gross_cost
    FROM {CUR_TABLE}
    WHERE line_item_product_code = '{product_code}'
        AND line_item_line_item_type = 'Usage'
        AND {partitions}
    GROUP BY
        line_item_resource_id,
        line_item_operation,
        line_item_usage_account_id,
        line_item_usage_type
    ORDER BY gross_cost DESC
    """

    # --- Query 2: Credits applied ---
    credits_query = f"""
    SELECT
        line_item_usage_type,
        line_item_line_item_description,
        SUM(line_item_unblended_cost) AS credit_amount
    FROM {CUR_TABLE}
    WHERE line_item_product_code = '{product_code}'
        AND line_item_line_item_type = 'Credit'
        AND {partitions}
    GROUP BY line_item_usage_type, line_item_line_item_description
    """

    # --- Query 3: Daily trend (for anomaly detection) ---
    daily_query = f"""
    SELECT
        DATE(line_item_usage_start_date) AS usage_date,
        line_item_operation,
        SUM(line_item_usage_amount) AS hours,
        SUM(line_item_unblended_cost) AS cost
    FROM {CUR_TABLE}
    WHERE line_item_product_code = '{product_code}'
        AND line_item_line_item_type = 'Usage'
        AND {partitions}
    GROUP BY DATE(line_item_usage_start_date), line_item_operation
    ORDER BY usage_date DESC
    LIMIT 90
    """

    space_results = _query_athena(athena_client, space_query)
    credit_results = _query_athena(athena_client, credits_query)
    daily_results = _query_athena(athena_client, daily_query)

    # --- Assemble cost summary ---
    # Per-space breakdown
    spaces = {}
    for row in space_results:
        resource_id = row.get('line_item_resource_id', 'unknown')
        # Extract space UUID from ARN: arn:aws:aidevops:region:account:agentspace/UUID
        space_uuid = resource_id.split('/')[-1] if '/' in resource_id else resource_id

        if space_uuid not in spaces:
            spaces[space_uuid] = {
                'resource_arn': resource_id,
                'account_id': row.get('line_item_usage_account_id', ''),
                'operations': {},
                'total_hours': 0,
                'gross_cost': 0,
            }

        operation = row.get('line_item_operation', 'UNKNOWN')
        hours = float(row.get('total_hours', 0))
        gross = float(row.get('gross_cost', 0))

        spaces[space_uuid]['operations'][operation] = {
            'hours': round(hours, 4),
            'gross_cost': round(gross, 2),
            'usage_type': row.get('line_item_usage_type', ''),
        }
        spaces[space_uuid]['total_hours'] += hours
        spaces[space_uuid]['gross_cost'] += gross

    # Round totals
    for space in spaces.values():
        space['total_hours'] = round(space['total_hours'], 4)
        space['gross_cost'] = round(space['gross_cost'], 2)

    # Credits summary
    total_credits = 0
    credit_details = []
    for row in credit_results:
        amount = float(row.get('credit_amount', 0))
        total_credits += amount
        credit_details.append({
            'usage_type': row.get('line_item_usage_type', ''),
            'description': row.get('line_item_line_item_description', ''),
            'amount': round(amount, 2),
        })

    # Daily trend
    daily_trend = []
    for row in daily_results:
        daily_trend.append({
            'date': row.get('usage_date', ''),
            'operation': row.get('line_item_operation', ''),
            'hours': round(float(row.get('hours', 0)), 4),
            'cost': round(float(row.get('cost', 0)), 2),
        })

    # Totals
    total_gross = sum(s['gross_cost'] for s in spaces.values())
    total_hours = sum(s['total_hours'] for s in spaces.values())

    return {
        'source': 'CUR',
        'period': f"{period_end.strftime('%Y-%m')}",
        'pricing_rate': '$30.00/hour ($0.0083/second)',
        'summary': {
            'total_hours': round(total_hours, 4),
            'total_agent_seconds': round(total_hours * 3600, 1),
            'gross_cost': round(total_gross, 2),
            'total_credits_applied': round(total_credits, 2),
            'agent_spaces_active': len(spaces),
            'accounts_active': len(set(s['account_id'] for s in spaces.values())),
        },
        'by_space': spaces,
        'credits': _build_credit_consumption(
            total_gross, total_credits, credit_details, daily_trend, period_end,
            es_charge_from_cur=_get_es_charge_from_cur(athena_client, period_end),
        ) if include_credits else {'note': 'Credits not applicable for this agent'},
        'daily_trend': daily_trend,
    }


def _enrich_via_cost_explorer(period_start: datetime, period_end: datetime, service_names: list = None, include_credits: bool = True) -> dict:
    """Fallback: Query Cost Explorer API for agent cost (less granular)."""
    ce = boto3.client('ce', region_name=REGION)

    if service_names is None:
        service_names = ['AWS DevOps Agent', 'AWSDevOpsAgent', 'DevOpsAgent']

    start_date = period_start.strftime('%Y-%m-%d')
    end_date = period_end.strftime('%Y-%m-%d')

    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='DAILY',
            Metrics=['UnblendedCost', 'UsageQuantity'],
            Filter={'Dimensions': {'Key': 'SERVICE', 'Values': service_names}},
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}],
        )

        by_type = {}
        total_cost = 0
        for period in resp.get('ResultsByTime', []):
            for group in period.get('Groups', []):
                usage_type = group['Keys'][0]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                usage = float(group['Metrics']['UsageQuantity']['Amount'])
                if usage_type not in by_type:
                    by_type[usage_type] = {'cost': 0, 'usage_hours': 0}
                by_type[usage_type]['cost'] += cost
                by_type[usage_type]['usage_hours'] += usage
                total_cost += cost

        # Build daily trend from CE results for credit consumption calc
        daily_trend = []
        for period_item in resp.get('ResultsByTime', []):
            day_date = period_item.get('TimePeriod', {}).get('Start', '')
            day_cost = sum(
                float(g['Metrics']['UnblendedCost']['Amount'])
                for g in period_item.get('Groups', [])
            )
            if day_cost > 0:
                daily_trend.append({'date': day_date, 'operation': 'ALL', 'hours': 0, 'cost': round(day_cost, 2)})

        return {
            'source': 'CostExplorer',
            'period': f"{start_date} to {end_date}",
            'pricing_rate': '$30.00/hour ($0.0083/second)',
            'summary': {
                'total_cost': round(total_cost, 2),
                'by_usage_type': {k: {'cost': round(v['cost'], 2), 'hours': round(v['usage_hours'], 4)} for k, v in by_type.items()},
            },
            'credits': _build_credit_consumption(total_cost, 0, [], daily_trend, period_end) if include_credits else {'note': 'Credits not applicable for this agent'},
            'note': 'CUR not configured — using Cost Explorer (no per-space or per-engineer breakdown available)',
        }

    except Exception as e:
        logger.warning("Cost Explorer query failed: %s", e)
        return {
            'source': 'unavailable',
            'error': str(e),
            'note': 'Neither CUR nor Cost Explorer returned data. Configure CUR for full cost attribution.',
        }


def handler(event, context):
    """Lambda entry point — retrieve per-agent cost data.

    Primary: CUR via Athena (per-space, per-operation, per-engineer, hourly).
    Fallback: Cost Explorer API (daily aggregates, no resource-level detail).

    Returns per-agent cost data. Credits apply only to DevOps Agent (75% ES charge).
    """

    now = datetime.now(timezone.utc)
    # Report covers last 24 hours, but cost data aligns to billing month
    period_end = now
    period_start = now - timedelta(hours=24)

    agents = get_active_agents()
    per_agent_cost = {}

    if CUR_DATABASE and CUR_TABLE and ATHENA_OUTPUT_BUCKET:
        logger.info("Using CUR via Athena (database=%s, table=%s, cross_account=%s)",
                    CUR_DATABASE, CUR_TABLE, bool(CUR_CROSS_ACCOUNT_ROLE_ARN))
        athena_client = _get_athena_client()

        for agent in agents:
            include_credits = (agent.name == 'devops')
            logger.info("Querying CUR for %s (product_code=%s, credits=%s)",
                        agent.display_name, agent.cur_product_code, include_credits)
            per_agent_cost[agent.name] = _enrich_via_cur(
                athena_client, period_start, period_end,
                product_code=agent.cur_product_code,
                include_credits=include_credits,
            )
            per_agent_cost[agent.name]['agent_display_name'] = agent.display_name
    else:
        logger.info("CUR not configured — falling back to Cost Explorer API")
        # CE fallback: try each agent with appropriate service name variants
        ce_service_names = {
            'devops': ['AWS DevOps Agent', 'AWSDevOpsAgent', 'DevOpsAgent'],
            'security': ['AWS Security Agent', 'AWSSecurityAgent', 'SecAgent'],
        }
        for agent in agents:
            svc_names = ce_service_names.get(agent.name, [agent.cur_product_code])
            include_credits = (agent.name == 'devops')
            per_agent_cost[agent.name] = _enrich_via_cost_explorer(period_start, period_end, service_names=svc_names, include_credits=include_credits)
            per_agent_cost[agent.name]['agent_display_name'] = agent.display_name

    # Log summary
    for name, data in per_agent_cost.items():
        logger.info("Cost enrichment %s: source=%s, gross_cost=%s",
                    name, data.get('source', 'N/A'),
                    data.get('summary', {}).get('gross_cost', 'N/A'))

    return per_agent_cost
