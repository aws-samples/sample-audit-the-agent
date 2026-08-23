# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Report generation — interactive executive dashboard.

Generates:
1. HTML dashboard — executive-focused with KPI cards, charts, filters, drill-down
2. JSON audit record — structured for SIEM ingestion (v2.0 schema)
3. SNS notification — summary for email delivery

Design principles:
- Numbers first, text second (executive audience)
- Interactive filters for enterprise-scale data
- Authorization & Risk Profile is the hero section (CISO priority)
- Credit consumption front and center (VP Engineering priority)
- Drill-down for details (don't bury, don't overwhelm)
"""

import json
import logging
import os
from datetime import datetime, timezone
from html import escape
from typing import Any
from agent_config import AGENT_TYPES_CONFIG, AGENT_REGISTRY

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get('REGION', 'us-east-1')
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET', '')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENABLE_URL_SHORTENING = os.environ.get('ENABLE_URL_SHORTENING', 'false').lower() == 'true'


def _risk_color(level: str) -> str:
    """Map risk level to color."""
    return {'GREEN': '#2E7D32', 'YELLOW': '#F9A825', 'ORANGE': '#E65100', 'RED': '#C62828'}.get(level, '#666')


def _sanitize_enum(value: str, allowed: set, default: str) -> str:
    """Sanitize a value to only allowed enum values (prevents XSS via Bedrock output).

    Args:
        value: Raw value from Bedrock JSON output.
        allowed: Set of valid values.
        default: Fallback if value is not in allowed set.

    Returns:
        Sanitized value guaranteed to be in the allowed set.
    """
    return value if value in allowed else default


_VALID_RISK_LEVELS = {'GREEN', 'YELLOW', 'ORANGE', 'RED'}
_VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
_VALID_PRIORITIES = {'HIGH', 'MEDIUM', 'LOW'}


def _get_scope_label() -> str:
    """Get human-readable scope label from AGENT_TYPES config.

    Returns:
        Scope string (e.g., "AWS DevOps Agent" or "DevOps + Security Agent").
    """
    agent_types = os.environ.get('AGENT_TYPES', 'devops').lower().strip()
    if agent_types == 'both':
        return 'AWS DevOps Agent + AWS Security Agent'
    elif agent_types == 'security':
        return 'AWS Security Agent'
    else:
        return 'AWS DevOps Agent'


def _alert_color(level: str) -> str:
    """Map credit alert level to color."""
    return {
        'HEALTHY': '#2E7D32', 'ELEVATED': '#F9A825',
        'ON_PACE_TO_EXCEED': '#E65100', 'EXCEEDED': '#C62828',
        'NOT_CONFIGURED': '#999',
    }.get(level, '#666')


def _fmt_days_until_exhaust(credits: dict) -> str:
    """Render the 'days until exhaust' state for the credit views.

    Credits are a monthly grant (75% of prior-month ES charge) that reset at
    month-end with no rollover, so "infinite" is never a valid outcome. This
    reads the explicit credit_status set in enrich so a countdown is only shown
    when credits will actually run out before the monthly reset. Falls back to
    interpreting days_until_exhaust directly for backward compatibility with
    older payloads that predate credit_status.
    """
    status = credits.get('credit_status')
    days = credits.get('days_until_exhaust')
    days_left = credits.get('days_remaining_in_month')

    if status == 'EXHAUSTED':
        return 'Exhausted'
    if status == 'NO_USAGE':
        return 'No usage this period'
    if status == 'NOT_CONFIGURED':
        return 'N/A'
    if status == 'SUFFICIENT':
        return (
            f'Sufficient through month-end ({days_left} days left)'
            if days_left is not None else 'Sufficient through month-end'
        )
    if status == 'WILL_EXHAUST' and isinstance(days, (int, float)):
        return f'{days:.0f} days'

    # Backward-compat fallback (no credit_status present)
    if days is None:
        return 'N/A'
    if isinstance(days, (int, float)):
        return 'Exhausted' if days <= 0 else f'{days:.0f} days'
    return 'N/A'


def _fmt_days_until_exhaust_compact(credits: dict) -> str:
    """Compact variant of the exhaust state for the small credit-grid metric cell.

    Returns a short token (e.g. "6 days", "Exhausted", "OK", "N/A") suitable for
    a large-number metric slot; the full phrasing lives in the summary line.
    """
    status = credits.get('credit_status')
    days = credits.get('days_until_exhaust')

    if status == 'EXHAUSTED':
        return 'Exhausted'
    if status == 'NO_USAGE':
        return 'No usage'
    if status == 'NOT_CONFIGURED':
        return 'N/A'
    if status == 'SUFFICIENT':
        return 'OK'
    if status == 'WILL_EXHAUST' and isinstance(days, (int, float)):
        return f'{days:.0f} days'

    if days is None:
        return 'N/A'
    if isinstance(days, (int, float)):
        return 'Exhausted' if days <= 0 else f'{days:.0f} days'
    return 'N/A'


def _build_kpi_cards(analysis: dict, credits: dict, collect: dict) -> str:
    """Build the executive KPI card grid.

    The overall-risk verdict is carried by the verdict banner and severity strip
    at the top of the report, so the KPI grid intentionally omits a risk card and
    focuses on the operational metrics (activity, credits, triggers) that a CISO
    scans after the verdict.
    """
    total_events = collect.get('total_events', 0)
    tasks = collect.get('tasks', [])
    triggers = collect.get('trigger_summary', {})

    # Credit metrics
    alert_level = credits.get('alert_level', 'NOT_CONFIGURED')
    consumption_pct = credits.get('consumption_pct', 0)
    burn_rate = credits.get('burn_rate_per_day', 0)
    budget = credits.get('monthly_credit_budget', 0)
    mtd = credits.get('mtd_usage', 0)

    return f'''
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-value">{len(tasks)}</div>
            <div class="kpi-label">Agent Tasks</div>
            <div class="kpi-sub">{total_events} total events</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value" style="color:{_alert_color(alert_level)}">{consumption_pct:.0f}%</div>
            <div class="kpi-label">Credit Consumption</div>
            <div class="kpi-sub">${mtd:,.0f} of ${budget:,.0f} budget</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value">${burn_rate:,.0f}</div>
            <div class="kpi-label">Daily Burn Rate</div>
            <div class="kpi-sub">{_fmt_days_until_exhaust(credits)}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-value">{sum(triggers.values())}</div>
            <div class="kpi-label">Triggers</div>
            <div class="kpi-sub">{", ".join(f"{k}: {v}" for k, v in triggers.items()) or "None"}</div>
        </div>
    </div>'''


def _build_trust_section(trust: dict) -> str:
    """Build the Trust Posture section with dimension bars."""
    tp = trust.get('trust_posture', {})
    assessments = trust.get('assessments', {})
    overall = tp.get('overall_risk', 'LOW')

    dims = []
    dim_config = [
        ('capability_level', 'Capability', 'What can the agent do?'),
        ('permission_scope', 'Permissions', 'How broad is its access?'),
        ('visibility_gaps', 'Visibility', 'Can we see everything it does?'),
        ('integration_exposure', 'Integrations', 'What external systems connect?'),
        ('human_approval', 'Human Approval', 'Are humans in the loop?'),
    ]

    for key, label, tooltip in dim_config:
        dim = assessments.get(key, {})
        risk = dim.get('risk_level', 'LOW')
        summary = escape(dim.get('summary', ''))
        color = _risk_color({'LOW': 'GREEN', 'MEDIUM': 'YELLOW', 'HIGH': 'ORANGE', 'CRITICAL': 'RED'}.get(risk, 'GREEN'))
        # Show "why" explanation for MEDIUM and above — LOW needs no justification
        why_html = ''
        if risk in ('MEDIUM', 'HIGH', 'CRITICAL') and summary:
            why_html = f'<div class="trust-why">→ {summary}</div>'

        # For capability dimension, add collapsible full role list
        detail_html = ''
        if key == 'capability_level' and dim.get('actions_roles'):
            roles_list = dim['actions_roles']
            if roles_list:
                role_items_parts = []
                for r in roles_list:
                    status = r.get('status', 'UNKNOWN')
                    bg = '#E8F5E9' if status == 'ACTIVE' else '#FFF3E0'
                    fg = '#2E7D32' if status == 'ACTIVE' else '#E65100'
                    rname = escape(r.get('role_name', ''))
                    rarn = escape(r.get('role_arn', ''))
                    fid = escape(r.get('finding_id', ''))
                    fid_html = f' <span class="finding-id" title="Finding ID — use in findings.csv to suppress/accept">{fid}</span>' if fid else ''
                    role_items_parts.append(
                        f'<li><span class="tag-pill" style="background:{bg};color:{fg}">{status}</span> '
                        f'<code>{rname}</code> <span class="muted">({rarn})</span>{fid_html}</li>'
                    )
                role_items = ''.join(role_items_parts)
                detail_html = f'''
                <div class="trust-detail">
                    <a class="trust-detail-toggle" onclick="this.nextElementSibling.classList.toggle(\'collapsed\');this.textContent=this.textContent===\'▶ Show all roles\'?\'▼ Hide roles\':\'▶ Show all roles\'">▶ Show all roles</a>
                    <ul class="trust-role-list collapsed">{role_items}</ul>
                </div>'''

        dims.append(f'''
            <div class="trust-dim" title="{summary}">
                <span class="trust-label">{label}</span>
                <span class="trust-bar" style="background:{color};width:{20 if risk=="LOW" else 50 if risk=="MEDIUM" else 80}%"></span>
                <span class="trust-risk">{risk}</span>
                {why_html}
                {detail_html}
            </div>''')

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('trust')">
            <h2>Agent Authorization &amp; Risk Profile</h2>
            <span class="trust-badge" style="background:{_risk_color({"LOW":"GREEN","MEDIUM":"YELLOW","HIGH":"ORANGE","CRITICAL":"RED"}.get(overall,"GREEN"))}">{overall}</span>
            <span class="chevron" id="chevron-trust">▼</span>
        </div>
        <div class="section-body" id="body-trust">
            <div class="trust-legend">
                <span>◀ LOW risk (narrow scope, read-only)</span>
                <span style="float:right">HIGH risk (broad scope, write access) ▶</span>
            </div>
            <div class="trust-dims">{"".join(dims)}</div>
            <div class="trust-guide">
                <small><b>How to read:</b> Capability = what can it do? · Permissions = how broad is access? · Visibility = can we see everything? · Integrations = what external systems connect? · Human Approval = are humans in the loop?</small>
            </div>
        </div>
    </div>'''


def _build_credit_section(credits: dict) -> str:
    """Build the credit consumption section with progress bar."""
    if credits.get('alert_level') == 'NOT_CONFIGURED':
        return '''
        <div class="section">
            <div class="section-header" onclick="toggleSection('credits')">
                <h2>Credit Consumption</h2>
                <span class="chevron" id="chevron-credits">▼</span>
            </div>
            <div class="section-body" id="body-credits">
                <p class="muted">Credit tracking not configured. Set <code>MonthlyESCharge</code> parameter to enable.</p>
            </div>
        </div>'''

    pct = credits.get('consumption_pct', 0)
    alert = credits.get('alert_level', 'HEALTHY')
    bar_color = _alert_color(alert)
    bar_width = min(pct, 100)

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('credits')">
            <h2>Credit Consumption</h2>
            <span class="trust-badge" style="background:{bar_color}">{alert}</span>
            <span class="chevron" id="chevron-credits">▼</span>
        </div>
        <div class="section-body" id="body-credits">
            <div class="credit-bar-container">
                <div class="credit-bar" style="width:{bar_width}%;background:{bar_color}"></div>
                <span class="credit-bar-label">{pct:.1f}% consumed</span>
            </div>
            <div class="credit-grid">
                <div><span class="credit-metric">${credits.get("monthly_credit_budget",0):,.0f}</span><br><small>Monthly Budget</small><br><small class="muted">({credits.get("budget_source", "75% of ES charge")})</small></div>
                <div><span class="credit-metric">${credits.get("mtd_usage",0):,.0f}</span><br><small>MTD Usage</small></div>
                <div><span class="credit-metric">${credits.get("burn_rate_per_day",0):,.0f}/day</span><br><small>Burn Rate</small></div>
                <div><span class="credit-metric">${credits.get("projected_month_total",0):,.0f}</span><br><small>Projected</small></div>
                <div><span class="credit-metric">${credits.get("credits_remaining",0):,.0f}</span><br><small>Remaining</small></div>
                <div><span class="credit-metric">{_fmt_days_until_exhaust_compact(credits)}</span><br><small>Until Exhaust</small></div>
            </div>
            <p class="summary-text">{escape(credits.get("summary", ""))}</p>
        </div>
    </div>'''


def _build_risk_section(analysis: dict) -> str:
    """Build the risk flags section."""
    flags = analysis.get('risk_flags', [])
    if not flags:
        return '''
        <div class="section">
            <div class="section-header" onclick="toggleSection('risks')">
                <h2>Risk Flags</h2>
                <span class="trust-badge" style="background:#2E7D32">NONE</span>
                <span class="chevron" id="chevron-risks">▶</span>
            </div>
            <div class="section-body collapsed" id="body-risks">
                <p class="muted">No risk flags raised this period. The agent operated within expected parameters — no unusual patterns, permission escalations, or cost anomalies detected.</p>
            </div>
        </div>'''

    rows = ''
    for f in flags:
        sev = _sanitize_enum(f.get('severity', 'LOW'), _VALID_SEVERITIES, 'LOW')
        color = {'HIGH': '#C62828', 'MEDIUM': '#E65100', 'LOW': '#F9A825'}.get(sev, '#666')
        rows += f'''
            <tr>
                <td><span class="sev-badge" style="background:{color}">{escape(sev)}</span></td>
                <td><b>{escape(f.get("flag",""))}</b><br><small>{escape(f.get("detail",""))}</small></td>
                <td><small>{escape(f.get("action",""))}</small></td>
            </tr>'''

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('risks')">
            <h2>Risk Flags ({len(flags)})</h2>
            <span class="chevron" id="chevron-risks">▼</span>
        </div>
        <div class="section-body" id="body-risks">
            <div class="section-guide">
                <b>What this shows:</b> Patterns in today's agent activity that may warrant attention. Each flag includes a severity (HIGH = act today, MEDIUM = review this week, LOW = awareness only), a finding description, and a suggested action.
            </div>
            <div class="ai-disclaimer">AI-inferred risk assessment (Amazon Bedrock) — review with caution. Cross-reference with your security policies before escalating.</div>
            <table class="risk-table">
                <tr><th>Sev</th><th>Finding</th><th>Action</th></tr>
                {rows}
            </table>
        </div>
    </div>'''


def _build_activity_section(collect: dict) -> str:
    """Build the interactive activity table with filters."""
    events = collect.get('events', [])
    tasks = collect.get('tasks', [])
    show_agent_col = AGENT_TYPES_CONFIG.lower().strip() == 'both'

    task_rows = ''
    for t in tasks:
        agent_col = f'<td><span class="tag-pill agent-tag">{escape(t.get("agent_type","")[:12])}</span></td>' if show_agent_col else ''
        task_rows += f'''
            <tr class="task-row">
                <td>{escape(t.get("triggered_at","")[:16])}</td>
                <td>{escape(t.get("triggered_by","")[:40])}</td>
                <td><span class="tag-pill">{escape(t.get("task_type",""))}</span></td>
                {agent_col}
                <td>{escape(t.get("trigger_type",""))}</td>
                <td>{escape(t.get("agent_space_id","")[:8])}</td>
                <td>{escape(t.get("status",""))}</td>
            </tr>'''

    agent_header = '<th>Agent</th>' if show_agent_col else ''

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('activity')">
            <h2>Agent Activity ({len(tasks)} tasks, {len(events)} events)</h2>
            <span class="chevron" id="chevron-activity">▶</span>
        </div>
        <div class="section-body collapsed" id="body-activity">
            <p class="scope-note">Scope: this audit focuses on <b>mutating (state-changing) operations</b> — the security-relevant actions where an agent creates, modifies, or deletes resources. Read-only calls are intentionally excluded to keep the review focused on actions that carry security and compliance weight.</p>
            <div class="filter-bar">
                <input type="text" id="taskSearch" placeholder="Search by user, type, space..." oninput="filterTasks()">
                <select id="typeFilter" onchange="filterTasks()">
                    <option value="">All Task Types</option>
                </select>
                <span id="taskCount" class="result-count"></span>
                <span id="pagination" class="pagination-controls"></span>
            </div>
            <table class="data-table" id="taskTable">
                <tr><th>Time</th><th>Who</th><th>Type</th>{agent_header}<th>Trigger</th><th>Space</th><th>Status</th></tr>
                {task_rows}
            </table>
        </div>
    </div>'''


def _build_authorization_section(analysis: dict) -> str:
    """Build the authorization chain section."""
    chain = analysis.get('authorization_chain', [])
    if not chain:
        return ''

    steps = ''
    for i, step in enumerate(chain):
        steps += f'''
            <div class="auth-step">
                <div class="auth-time">{escape(str(step.get("time","")))}</div>
                <div class="auth-detail">
                    <b>{escape(step.get("who",""))}</b> — {escape(step.get("what",""))}
                    <br><small class="muted">{escape(step.get("how",""))}{" · " + escape(step.get("space","")) if step.get("space") else ""}</small>
                </div>
            </div>'''

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('auth')">
            <h2>Authorization Chain</h2>
            <span class="chevron" id="chevron-auth">▶</span>
        </div>
        <div class="section-body collapsed" id="body-auth">
            <div class="auth-chain">{steps}</div>
        </div>
    </div>'''


def _build_recommendations_section(analysis: dict) -> str:
    """Build recommendations section, grouped into action time-horizon buckets.

    Follows the ARIA convention of ordering recommendations by urgency
    (Immediate / Short-Term / Medium-Term) rather than a flat list, so a CISO
    reads them in the order they'd act. The bucket is a *presentational* mapping
    from the underlying priority (HIGH/MEDIUM/LOW) emitted by Bedrock — the data
    contract is unchanged; only the label and grouping differ.
    """
    recs = analysis.get('recommendations', [])
    if not recs:
        return ''

    # priority (data) -> (bucket label, badge color), in urgency order
    buckets = [
        ('HIGH', 'IMMEDIATE', '#C62828'),
        ('MEDIUM', 'SHORT-TERM', '#E65100'),
        ('LOW', 'MEDIUM-TERM', '#F9A825'),
    ]
    grouped = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for r in recs:
        pri = _sanitize_enum(r.get('priority', 'MEDIUM'), _VALID_PRIORITIES, 'MEDIUM')
        grouped[pri].append(r)

    items = ''
    for pri, label, color in buckets:
        group = grouped[pri]
        if not group:
            continue
        rows = ''
        for r in group:
            rows += f'''
            <div class="rec-item">
                <span class="sev-badge" style="background:{color}">{escape(label)}</span>
                <div>
                    <b>{escape(r.get("action",""))}</b>
                    <br><small class="muted">{escape(r.get("rationale",""))}</small>
                </div>
            </div>'''
        items += f'''
            <div class="rec-bucket">
                <div class="rec-bucket-head" style="color:{color}">{escape(label)} ({len(group)})</div>
                {rows}
            </div>'''

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('recs')">
            <h2>Recommendations ({len(recs)})</h2>
            <span class="chevron" id="chevron-recs">▶</span>
        </div>
        <div class="section-body collapsed" id="body-recs">
            <div class="ai-disclaimer">AI-inferred recommendations (Amazon Bedrock) — review with caution before acting. Validate against your operational context.</div>
            {items}
        </div>
    </div>'''



def _build_suppressed_section(trust: dict) -> str:
    """Build the collapsed 'Suppressed & Accepted' section.

    Suppressed and accepted findings are never fully hidden — they live in a
    collapsed section with their reason and provenance, so the report stays
    audit-complete and posture is never silently zeroed.
    """
    suppressed = trust.get('suppressed_findings', [])
    accepted = trust.get('accepted_findings', [])
    if not suppressed and not accepted:
        return ''

    def _rows(items, decision_label):
        parts = []
        for f in items:
            parts.append(
                f'<tr>'
                f'<td><span class="finding-id">{escape(f.get("finding_id", ""))}</span></td>'
                f'<td>{escape(f.get("dimension", ""))}</td>'
                f'<td>{escape(f.get("finding", ""))}</td>'
                f'<td><span class="decision-badge decision-{decision_label}">{decision_label.upper()}</span></td>'
                f'<td>{escape(f.get("decision_reason", ""))}</td>'
                f'<td class="muted">{escape(f.get("decision_by", ""))}</td>'
                f'</tr>'
            )
        return ''.join(parts)

    rows = _rows(accepted, 'accept') + _rows(suppressed, 'suppress')

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('suppressed')">
            <h2>Suppressed &amp; Accepted ({len(accepted)} accepted, {len(suppressed)} suppressed)</h2>
            <span class="chevron" id="chevron-suppressed">▶</span>
        </div>
        <div class="section-body collapsed" id="body-suppressed">
            <p class="muted" style="font-size:12px;margin-bottom:8px;">These findings were reviewed and dismissed or accepted by a human. They are excluded from the active findings list but retained here for audit completeness. A decision auto-resurfaces if the underlying finding's state changes.</p>
            <table class="data-table">
                <tr><th>Finding ID</th><th>Dimension</th><th>Finding</th><th>Decision</th><th>Reason</th><th>By</th></tr>
                {rows}
            </table>
        </div>
    </div>'''


def _build_per_agent_sections(per_agent_cost: dict, collect: dict) -> str:
    """Build per-agent cost and activity sections when multiple agents are active.

    Only renders when more than one agent is present. Each agent gets its own
    card showing activity count, cost, and (for DevOps) credit status.
    """
    if len(per_agent_cost) <= 1:
        return ''  # Single agent — no split needed


    # Count events per agent from collect data
    events = collect.get('events', [])
    agent_event_counts = {}
    for evt in events:
        agent_type = evt.get('agent_type', 'Unknown Agent')
        agent_event_counts[agent_type] = agent_event_counts.get(agent_type, 0) + 1

    sections_html = '<div class="agent-split-container" id="agents">\n'

    for agent_name, cost_data in per_agent_cost.items():
        agent_cfg = AGENT_REGISTRY.get(agent_name)
        display_name = cost_data.get('agent_display_name', agent_cfg.display_name if agent_cfg else agent_name)

        summary = cost_data.get('summary', {})
        gross_cost = summary.get('gross_cost', summary.get('total_cost', 0))
        total_hours = summary.get('total_hours', 0)
        spaces_active = summary.get('agent_spaces_active', 0)
        source = cost_data.get('source', 'unavailable')

        # Event count for this agent
        event_count = agent_event_counts.get(display_name, 0)

        # Credits (DevOps only)
        credits = cost_data.get('credits', {})
        has_credits = credits.get('alert_level') and credits.get('alert_level') != 'NOT_CONFIGURED'

        sections_html += f'''
        <div class="agent-card">
            <h3>{escape(display_name)}</h3>
            <div class="agent-metrics">
                <div><span class="agent-metric-value">{event_count}</span><br><small>Events</small></div>
                <div><span class="agent-metric-value">{spaces_active}</span><br><small>Spaces</small></div>
                <div><span class="agent-metric-value">{total_hours:.1f}h</span><br><small>Usage</small></div>
                <div><span class="agent-metric-value">${gross_cost:,.0f}</span><br><small>Gross Cost</small></div>
            </div>
'''
        if has_credits:
            pct = credits.get('consumption_pct', 0)
            alert = credits.get('alert_level', 'HEALTHY')
            alert_class = 'green' if alert == 'HEALTHY' else 'orange' if alert == 'WARNING' else 'red'
            sections_html += f'''
            <div class="agent-credit-bar">
                <div class="credit-bar-bg"><div class="credit-bar-fill credit-{alert_class}" style="width:{min(pct,100):.0f}%"></div></div>
                <small>{pct:.0f}% credit consumed · {_fmt_days_until_exhaust(credits)}</small>
            </div>
'''
        elif agent_name != 'devops':
            sections_html += '            <div class="agent-credit-bar"><small class="muted">No credit offset — full billing applies</small></div>\n'

        if source == 'unavailable':
            sections_html += '            <div class="agent-credit-bar"><small class="muted">Cost data not yet available (configure CUR)</small></div>\n'

        sections_html += '        </div>\n'

    sections_html += '</div>\n'
    return sections_html


def _build_space_cost_section(per_agent_cost: dict, credits: dict = None) -> str:
    """Build the consolidated Agent Space Cost Breakdown section.

    Surfaces the per-agent-space cost the pipeline already captures (enrich's
    `by_space` / name-resolved `by_space_named`) but which was otherwise never
    shown — the report previously displayed only the space *count*. One table
    consolidates spaces across every agent (DevOps, Security) with an Agent Type
    column, sorted by usage cost descending so the highest-spend space is first
    (the actionable order).

    Columns: Usage Cost is the actual (unblended) usage cost. "% of Credit Budget"
    shows each DevOps space's cost as a share of the org-wide DevOps Agent credit
    budget (75% of monthly ES charge, consolidated billing) — the biggest-driver
    signal against the credit envelope. Credits are DevOps-Agent-only, so Security
    Agent spaces show N/A. Tags are the space's own purpose/grouping labels
    (application, environment, on-call team) from the Agent Space configuration.

    Per-space granularity only exists on the CUR path; the Cost Explorer
    fallback has no `by_space`, so when no agent has space data we render a
    guidance note pointing at CUR configuration rather than an empty table.
    """
    credit_budget = float((credits or {}).get('monthly_credit_budget', 0) or 0)
    rows = []
    any_cur_source = False
    for agent_name, cost_data in (per_agent_cost or {}).items():
        if not isinstance(cost_data, dict):
            continue
        if cost_data.get('source') == 'CUR':
            any_cur_source = True
        display_name = cost_data.get(
            'agent_display_name',
            AGENT_REGISTRY.get(agent_name).display_name if AGENT_REGISTRY.get(agent_name) else agent_name,
        )
        # Credit budget is DevOps-Agent-only (consolidated billing, org-wide).
        is_devops = str(agent_name).lower() == 'devops'
        # Prefer name-resolved spaces from aggregate; fall back to raw UUID-keyed.
        by_space = cost_data.get('by_space_named') or cost_data.get('by_space') or {}
        for space_key, sdata in by_space.items():
            if not isinstance(sdata, dict):
                continue
            # If we only have the raw UUID key (no resolved name), shorten it.
            space_label = space_key if cost_data.get('by_space_named') else f'space-{str(space_key)[:8]}'
            tags = sdata.get('tags', {}) or {}
            # Render user tags as compact key=value pairs (purpose/grouping:
            # application, environment, on-call team, etc.). Not an "owner".
            # Exclude AWS-reserved (aws:*) tags defensively.
            tag_pairs = [f'{k}={v}' for k, v in tags.items()
                         if v not in (None, '') and not str(k).lower().startswith('aws:')]
            tags_label = ' · '.join(tag_pairs[:3]) if tag_pairs else '—'
            cost = float(sdata.get('gross_cost', 0) or 0)
            # % of credit budget: DevOps only, and only when a budget exists.
            if is_devops and credit_budget > 0:
                pct_budget = f'{cost / credit_budget * 100:.1f}%'
            elif is_devops:
                pct_budget = '—'  # DevOps but no configured budget
            else:
                pct_budget = 'N/A'  # Security Agent has no credit pool
            rows.append({
                'space': space_label,
                'agent': display_name,
                'account': sdata.get('account_id', ''),
                'hours': float(sdata.get('total_hours', 0) or 0),
                'cost': cost,
                'pct_budget': pct_budget,
                'tags': tags_label,
            })

    # No per-space data anywhere → guidance note (CE fallback or no spend).
    if not rows:
        note = ('Per-space cost breakdown requires the CUR (Cost & Usage Report) data source. '
                'Configure <code>CUR_DATABASE</code> / <code>CUR_TABLE</code> to enable per-agent-space attribution.'
                ) if not any_cur_source else 'No agent-space cost recorded for this period.'
        return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('spaces')">
            <h2>Agent Space Cost Breakdown</h2>
            <span class="chevron" id="chevron-spaces">▶</span>
        </div>
        <div class="section-body collapsed" id="body-spaces">
            <p class="muted">{note}</p>
        </div>
    </div>'''

    rows.sort(key=lambda r: r['cost'], reverse=True)
    body_rows = ''
    for r in rows:
        body_rows += f'''
            <tr>
                <td><b>{escape(str(r["space"]))}</b></td>
                <td>{escape(str(r["agent"]))}</td>
                <td><code>{escape(str(r["account"]))}</code></td>
                <td class="num">{r["hours"]:.1f}h</td>
                <td class="num">${r["cost"]:,.2f}</td>
                <td class="num">{escape(str(r["pct_budget"]))}</td>
                <td>{escape(str(r["tags"]))}</td>
            </tr>'''

    total_cost = sum(r['cost'] for r in rows)
    total_hours = sum(r['hours'] for r in rows)
    total_pct = f'{total_cost / credit_budget * 100:.1f}%' if credit_budget > 0 else '—'

    return f'''
    <div class="section">
        <div class="section-header" onclick="toggleSection('spaces')">
            <h2>Agent Space Cost Breakdown ({len(rows)})</h2>
            <span class="chevron" id="chevron-spaces">▶</span>
        </div>
        <div class="section-body collapsed" id="body-spaces">
            <div class="section-guide">
                <b>What this shows:</b> Per-agent-space usage cost across all agents this period, highest spend first. <b>% of Credit Budget</b> is each DevOps space's cost as a share of the org-wide DevOps Agent credit budget (75% of monthly Enterprise Support charge) — showing which spaces drive credit consumption. Credits are DevOps-Agent-only, so Security Agent spaces show N/A. <b>Tags</b> are the space's own purpose labels (application, environment, on-call team) from the Agent Space configuration.
            </div>
            <table class="risk-table">
                <thead>
                    <tr><th>Agent Space</th><th>Agent Type</th><th>Account</th><th class="num">Usage</th><th class="num">Usage Cost</th><th class="num">% of Credit Budget</th><th>Tags</th></tr>
                </thead>
                <tbody>
                    {body_rows}
                    <tr class="space-total">
                        <td><b>Total</b></td><td></td><td></td>
                        <td class="num"><b>{total_hours:.1f}h</b></td>
                        <td class="num"><b>${total_cost:,.2f}</b></td>
                        <td class="num"><b>{total_pct}</b></td>
                        <td></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>'''


def _verdict_banner(risk_level: str, analysis: dict) -> str:
    """Render the top-of-report verdict band (WASEC verdict-forward framing).

    Leads with the overall risk verdict so a CISO sees the bottom line before
    any detail. Color is driven strictly by the risk palette via _risk_color so
    the banner reinforces the same GREEN/YELLOW/ORANGE/RED language used
    throughout the risk sections.
    """
    verdict_word = {
        'GREEN': 'LOW RISK',
        'YELLOW': 'MODERATE RISK',
        'ORANGE': 'ELEVATED RISK',
        'RED': 'HIGH RISK',
    }.get(risk_level, 'LOW RISK')
    verdict_sub = {
        'GREEN': 'No material concerns detected this period.',
        'YELLOW': 'Some findings warrant review.',
        'ORANGE': 'Findings require attention before next cycle.',
        'RED': 'Immediate review recommended.',
    }.get(risk_level, 'No material concerns detected this period.')
    color = _risk_color(risk_level)
    return (
        f'<div class="verdict-banner" style="border-left:6px solid {color};">'
        f'<span class="verdict-word" style="color:{color};">{verdict_word}</span>'
        f'<span class="verdict-sub">{verdict_sub}</span>'
        f'</div>'
    )


def _masthead(report_id: str, generated_at: str) -> str:
    """Render the report masthead (title band + audience/provenance line).

    Modeled on the ARIA customer-report convention: a titled band that names the
    report, marks the intended audience/classification, states the date and
    scope, and carries an explicit "automated analysis — verify" provenance line
    at the top rather than only inside per-section disclaimers. This is what
    shifts the artifact from "tool output" to an executive document.
    """
    scope = escape(_get_scope_label())
    return f'''
    <div class="masthead">
        <div class="masthead-titlerow">
            <h1>AuditTheAgent Daily Report</h1>
            <span class="audience-badge">CONFIDENTIAL · FOR INTENDED RECIPIENT</span>
        </div>
        <p class="masthead-sub">AI Agent Governance · {escape(report_id)} · {escape(generated_at)} · Scope: {scope}</p>
        <p class="masthead-provenance">Findings based on automated analysis (Amazon Bedrock) — verify before acting.</p>
    </div>'''


def _severity_strip(analysis: dict) -> str:
    """Render the severity distribution strip (ARIA scorecard convention).

    The verdict banner gives the single bottom-line verdict; this strip shows
    the *shape* of risk — how many findings at each severity plus the total
    assessed — so a CISO sees distribution, not just a headline. Counts are
    derived from the same risk_flags the Risk Flags section renders, and each
    cell uses the shared severity palette for consistency.
    """
    flags = analysis.get('risk_flags', [])
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in flags:
        sev = _sanitize_enum(f.get('severity', 'LOW'), _VALID_SEVERITIES, 'LOW')
        counts[sev] += 1
    # Severity → palette (CRITICAL and HIGH share the red family; MEDIUM orange; LOW yellow)
    sev_color = {'CRITICAL': '#8E0000', 'HIGH': '#C62828', 'MEDIUM': '#E65100', 'LOW': '#F9A825'}
    cells = ''
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        n = counts[sev]
        dim = '' if n else ' strip-cell-empty'
        cells += (
            f'<div class="strip-cell{dim}">'
            f'<span class="strip-count" style="color:{sev_color[sev]};">{n}</span>'
            f'<span class="strip-label">{sev}</span>'
            f'</div>'
        )
    total = len(flags)
    cells += (
        f'<div class="strip-cell strip-total">'
        f'<span class="strip-count">{total}</span>'
        f'<span class="strip-label">Findings Assessed</span>'
        f'</div>'
    )
    return f'<div class="severity-strip">{cells}</div>'


def _section_nav(analysis: dict, trust: dict, credits: dict, per_agent_cost: dict) -> str:
    """Render an inline section jump-list (ARIA left-nav convention, inline form).

    Links use the existing `body-{key}` element ids and a gotoSection() helper
    that expands a collapsed section before scrolling, so navigation works even
    though most sections start collapsed. Only sections that are actually
    rendered are listed — several sections (per-agent split, authorization
    chain, recommendations, suppressed) return empty and are omitted from the
    DOM when they have no data, so the nav must apply the same conditions or a
    chip would point at a section that doesn't exist and do nothing when clicked.
    """
    items = [('trust', 'Authorization & Risk'), ('credits', 'Credits')]
    # Per-agent split only renders when there is per-agent cost data.
    if per_agent_cost:
        items.append(('agents', 'Per-Agent'))
    # Space cost breakdown always renders (table or a CUR-guidance note).
    items.append(('spaces', 'Space Costs'))
    items += [('risks', 'Risk Flags'), ('activity', 'Activity')]
    # Authorization Chain section is omitted when the chain is empty.
    if analysis.get('authorization_chain'):
        items.append(('auth', 'Authorization Chain'))
    # Recommendations section is omitted when there are no recommendations.
    if analysis.get('recommendations'):
        items.append(('recs', 'Recommendations'))
    # Suppressed section only renders when accepted/suppressed findings exist.
    supp = trust.get('suppression_summary', {})
    if supp.get('accepted_count') or supp.get('suppressed_count'):
        items.append(('suppressed', 'Suppressed & Accepted'))
    items.append(('appendix', 'Methodology'))

    links = ''.join(
        f'<a class="nav-chip" id="navchip-{key}" data-key="{key}" href="javascript:void(0)" onclick="gotoSection(\'{key}\')">{escape(label)}</a>'
        for key, label in items
    )
    return f'<nav class="section-nav" aria-label="Report sections">{links}</nav>'


def _build_html(report_id: str, analysis: dict, trust: dict, credits: dict, collect: dict, per_agent_cost: dict = None) -> str:
    """Assemble the full interactive HTML dashboard."""
    generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    risk_level = _sanitize_enum(analysis.get('risk_level', 'GREEN'), _VALID_RISK_LEVELS, 'GREEN')

    kpi_cards = _build_kpi_cards(analysis, credits, collect)
    trust_section = _build_trust_section(trust)
    credit_section = _build_credit_section(credits)
    risk_section = _build_risk_section(analysis)
    activity_section = _build_activity_section(collect)
    auth_section = _build_authorization_section(analysis)
    recs_section = _build_recommendations_section(analysis)
    agent_sections = _build_per_agent_sections(per_agent_cost or {}, collect)
    space_cost_section = _build_space_cost_section(per_agent_cost or {}, credits)
    suppressed_section = _build_suppressed_section(trust)
    exec_summary = escape(analysis.get('executive_summary', ''))
    verdict_banner = _verdict_banner(risk_level, analysis)
    masthead = _masthead(report_id, generated_at)
    severity_strip = _severity_strip(analysis)
    section_nav = _section_nav(analysis, trust, credits, per_agent_cost or {})

    # Banner note when accepted risks exist — posture is never silently zeroed
    supp_summary = trust.get('suppression_summary', {})
    accepted_n = supp_summary.get('accepted_count', 0)
    accepted_high_n = supp_summary.get('accepted_high_count', 0)
    accepted_banner = ''
    if accepted_n:
        high_part = f" ({accepted_high_n} HIGH)" if accepted_high_n else ""
        accepted_banner = f'<div class="accepted-banner">{accepted_n} finding(s) accepted as known risk{high_part} — see Suppressed &amp; Accepted section.</div>'

    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuditTheAgent — {report_id}</title>
<style>
:root {{ --bg: #F8F9FA; --card: #FFF; --border: #E8EAED; --text: #202124; --muted: #5F6368; --blue: #1A73E8; --accent: #3C4043; --green: #2E7D32; --orange: #E65100; --red: #C62828; --yellow: #F9A825; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; padding: 24px; max-width: 1200px; margin: 0 auto; }}
.masthead {{ margin-bottom: 20px; }}
.masthead-titlerow {{ display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }}
.audience-badge {{ font-size: 10px; font-weight: 700; letter-spacing: 0.8px; color: var(--muted); border: 1px solid var(--border); border-radius: 4px; padding: 3px 8px; text-transform: uppercase; }}
.masthead-sub {{ color: var(--muted); font-size: 13px; margin-top: 6px; }}
.masthead-provenance {{ color: var(--muted); font-size: 12px; font-style: italic; margin-top: 2px; }}
.verdict-banner {{ display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; background: var(--card); border-radius: 10px; padding: 18px 24px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }}
.verdict-word {{ font-size: 22px; font-weight: 800; letter-spacing: 0.5px; }}
.verdict-sub {{ font-size: 14px; color: var(--muted); }}
.severity-strip {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1px; background: var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }}
.strip-cell {{ background: var(--card); padding: 14px 10px; text-align: center; display: flex; flex-direction: column; gap: 4px; }}
.strip-cell-empty {{ opacity: 0.5; }}
.strip-total {{ background: #F1F3F4; }}
.strip-count {{ font-size: 24px; font-weight: 800; font-variant-numeric: tabular-nums; }}
.strip-label {{ font-size: 10px; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase; color: var(--muted); }}
.section-nav {{ position: sticky; top: 0; z-index: 20; display: flex; flex-wrap: wrap; gap: 4px; margin: 0 -24px 24px; padding: 10px 24px; background: rgba(248,249,250,0.95); backdrop-filter: blur(6px); border-bottom: 1px solid var(--border); }}
.nav-chip {{ font-size: 13px; font-weight: 600; color: var(--muted); text-decoration: none; padding: 8px 14px; border-bottom: 2px solid transparent; transition: color 0.15s, border-color 0.15s; }}
.nav-chip:hover {{ color: var(--accent); border-bottom-color: var(--border); }}
.nav-chip.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
h1 {{ font-size: 26px; font-weight: 800; margin-bottom: 4px; letter-spacing: -0.2px; }}
.subtitle {{ color: var(--muted); font-size: 13px; margin-bottom: 24px; }}
.exec-summary {{ background: var(--card); border-radius: 12px; padding: 16px 20px; margin-bottom: 24px; border-left: 4px solid {_risk_color(risk_level)}; box-shadow: 0 1px 4px rgba(0,0,0,0.06); font-size: 14px; }}

/* KPI Grid */
.kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.kpi-card {{ background: var(--card); border-radius: 12px; border-top: 3px solid var(--accent); padding: 18px 20px; text-align: left; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }}
.kpi-value {{ font-size: 28px; font-weight: 800; font-variant-numeric: tabular-nums; }}
.kpi-label {{ font-size: 11px; color: var(--muted); margin-top: 6px; text-transform: uppercase; letter-spacing: 0.6px; font-weight: 700; }}
.kpi-sub {{ font-size: 11px; color: var(--muted); margin-top: 3px; }}

/* Sections */
.section {{ background: var(--card); border-radius: 12px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); overflow: hidden; scroll-margin-top: 60px; }}
.section-header {{ display: flex; align-items: center; gap: 12px; padding: 16px 20px; cursor: pointer; user-select: none; }}
.section-header:hover {{ background: #F1F3F4; }}
.section-header h2 {{ font-size: 13px; font-weight: 700; flex: 1; text-transform: uppercase; letter-spacing: 0.6px; color: var(--accent); }}
.section-body {{ padding: 0 20px 20px; }}
.section-body.collapsed {{ display: none; }}
.chevron {{ font-size: 12px; color: var(--muted); transition: transform 0.2s; }}

/* Trust Posture */
/* Per-Agent Split */
.agent-split-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 24px; scroll-margin-top: 60px; }}
.agent-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
.agent-card h3 {{ font-size: 16px; margin-bottom: 12px; }}
.agent-metrics {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }}
.agent-metric-value {{ font-size: 20px; font-weight: 700; color: var(--accent); }}
.agent-credit-bar {{ margin-top: 8px; }}
.credit-bar-bg {{ height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; margin-bottom: 4px; }}
.credit-bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
.credit-green {{ background: var(--green); }}
.credit-orange {{ background: var(--orange); }}
.credit-red {{ background: var(--red); }}
.trust-badge {{ background: var(--green); color: white; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
.trust-legend {{ display: flex; justify-content: space-between; font-size: 10px; color: var(--muted); margin-bottom: 8px; padding: 4px 0; border-bottom: 1px solid var(--border); }}
.trust-dims {{ display: flex; flex-direction: column; gap: 8px; }}
.trust-dim {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.trust-label {{ width: 120px; font-size: 12px; color: var(--muted); }}
.trust-bar {{ height: 8px; border-radius: 4px; min-width: 20px; transition: width 0.3s; }}
.trust-why {{ width: 100%; padding-left: 132px; font-size: 11px; color: var(--muted); font-style: italic; margin-top: -4px; }}
.trust-detail {{ width: 100%; padding-left: 132px; margin-top: 4px; }}
.trust-detail-toggle {{ font-size: 11px; color: var(--blue); cursor: pointer; text-decoration: none; }}
.trust-role-list {{ font-size: 11px; margin-top: 4px; padding-left: 16px; list-style: none; }}
.trust-role-list li {{ padding: 2px 0; }}
.trust-role-list.collapsed {{ display: none; }}
.finding-id {{ font-family: monospace; font-size: 10px; color: var(--muted); background: #F1F3F4; padding: 1px 5px; border-radius: 3px; }}
.accepted-banner {{ background: #FFF8E1; border-left: 4px solid var(--yellow); padding: 10px 14px; margin-bottom: 16px; border-radius: 4px; font-size: 13px; }}
.decision-badge {{ padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; color: #fff; }}
.decision-accept {{ background: var(--orange); }}
.decision-suppress {{ background: var(--muted); }}
.trust-risk {{ font-size: 11px; font-weight: 600; }}
.trust-guide {{ margin-top: 12px; padding: 8px; background: #F8F9FA; border-radius: 6px; color: var(--muted); }}
.section-guide {{ padding: 8px 12px; background: #F8F9FA; border-radius: 6px; font-size: 12px; color: var(--muted); margin-bottom: 12px; }}

/* Credit Consumption */
.credit-bar-container {{ background: #E8EAED; border-radius: 8px; height: 24px; position: relative; margin-bottom: 16px; overflow: hidden; }}
.credit-bar {{ height: 100%; border-radius: 8px; transition: width 0.5s; }}
.credit-bar-label {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 11px; font-weight: 600; }}
.credit-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 12px; }}
.credit-metric {{ font-size: 18px; font-weight: 700; }}
.summary-text {{ font-size: 13px; color: var(--muted); margin-top: 8px; }}

/* Risk Table */
.risk-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.risk-table th {{ text-align: left; padding: 8px; background: #F8F9FA; font-size: 11px; text-transform: uppercase; }}
.risk-table td {{ padding: 10px 8px; border-top: 1px solid var(--border); vertical-align: top; }}
.risk-table td.num, .risk-table th.num {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
.space-total td {{ border-top: 2px solid var(--border); background: #F8F9FA; }}
.sev-badge {{ color: white; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; white-space: nowrap; }}

/* Activity */
.filter-bar {{ display: flex; gap: 12px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }}
.filter-bar input, .filter-bar select {{ padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; }}
.filter-bar input {{ width: 260px; }}
.result-count {{ font-size: 12px; color: var(--muted); }}
.pagination-controls {{ font-size: 12px; margin-left: auto; }}
.pagination-controls a {{ color: var(--blue); text-decoration: none; padding: 4px 8px; }}
.data-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
.data-table th {{ text-align: left; padding: 8px; background: #F8F9FA; font-size: 11px; text-transform: uppercase; }}
.data-table td {{ padding: 8px; border-top: 1px solid var(--border); }}
.tag-pill {{ background: #E3F2FD; color: var(--blue); padding: 2px 8px; border-radius: 10px; font-size: 11px; }}

/* Auth Chain */
.auth-chain {{ border-left: 3px solid var(--accent); padding-left: 16px; }}
.auth-step {{ margin-bottom: 12px; padding: 8px 0; }}
.auth-time {{ font-size: 11px; color: var(--accent); font-weight: 600; }}
.auth-detail {{ font-size: 13px; }}

/* Recommendations */
.rec-item {{ display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid var(--border); }}
.rec-item:last-child {{ border-bottom: none; }}
.rec-bucket {{ margin-bottom: 16px; }}
.rec-bucket:last-child {{ margin-bottom: 0; }}
.rec-bucket-head {{ font-size: 11px; font-weight: 800; letter-spacing: 0.6px; text-transform: uppercase; margin-bottom: 4px; }}

/* Utils */
.muted {{ color: var(--muted); }}
.scope-note {{ font-size: 12px; color: var(--muted); background: #F1F3F4; border-left: 3px solid var(--accent); padding: 8px 12px; margin-bottom: 12px; border-radius: 4px; }}
.ai-disclaimer {{ background: #FFF3E0; border-left: 4px solid var(--orange); padding: 10px 14px; margin-bottom: 16px; border-radius: 4px; font-size: 12px; color: #5D4037; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 11px; text-align: center; }}
.footer-line {{ margin-bottom: 3px; }}
code {{ background: #F0F0F0; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
</style></head><body>

{masthead}
{verdict_banner}
{severity_strip}
{section_nav}

<div class="exec-summary">{exec_summary}</div>
{accepted_banner}

{kpi_cards}
{trust_section}
{agent_sections}
{space_cost_section}
{credit_section}
{risk_section}
{activity_section}
{auth_section}
{recs_section}
{suppressed_section}

<div class="section">
    <div class="section-header" onclick="toggleSection('appendix')">
        <h2>Authorization &amp; Risk Scoring Methodology</h2>
        <span class="chevron" id="chevron-appendix">▶</span>
    </div>
    <div class="section-body collapsed" id="body-appendix">
        <p style="font-size:12px;color:var(--muted);margin-bottom:12px;">Reference rubric for how each risk dimension is scored.</p>
        <table class="risk-table">
            <thead>
                <tr><th>Dimension</th><th>LOW</th><th>MEDIUM</th><th>HIGH</th><th>CRITICAL</th></tr>
            </thead>
            <tbody>
                <tr>
                    <td><b>Capability</b></td>
                    <td>Read-only roles only</td>
                    <td>Actions-capable roles exist</td>
                    <td>—</td>
                    <td>—</td>
                </tr>
                <tr>
                    <td><b>Permissions</b></td>
                    <td>No sensitive permissions</td>
                    <td>Moderate risk (S3 write, Lambda invoke)</td>
                    <td>Broad access (iam:*, ec2:*, admin-level)</td>
                    <td>—</td>
                </tr>
                <tr>
                    <td><b>Visibility</b></td>
                    <td>No private connections</td>
                    <td>Active connections, logs present</td>
                    <td>Gaps in logging or mTLS</td>
                    <td>Self-managed, no audit trail</td>
                </tr>
                <tr>
                    <td><b>Integrations</b></td>
                    <td>All triggers identifiable</td>
                    <td>Lambda-based automation</td>
                    <td>Unknown trigger sources</td>
                    <td>—</td>
                </tr>
                <tr>
                    <td><b>Human Approval</b></td>
                    <td>Approvals detected or read-only agent</td>
                    <td>—</td>
                    <td>Zero approvals with mutating capability</td>
                    <td>—</td>
                </tr>
            </tbody>
        </table>
        <p style="font-size:11px;color:var(--muted);margin-top:12px;">Overall posture = highest risk across all dimensions. One HIGH dimension → overall HIGH.</p>
    </div>
</div>

<div class="footer">
    <div class="footer-line">AuditTheAgent · AI Agent Governance · {report_id} · {generated_at} · Scope: {_get_scope_label()}</div>
    <div class="footer-line">CONFIDENTIAL — for intended recipient. AI-generated (Amazon Bedrock) — verify before acting.</div>
    <div class="footer-line">Data: CloudTrail + CUR + IAM · Analysis: Amazon Bedrock (Claude) · <a href="https://github.com/aws-samples/sample-audit-the-agent">GitHub</a></div>
    <small>This is sample code for demonstration purposes. Not intended for production use without thorough review and hardening. Validate all outputs before making operational decisions.</small>
</div>

<script>
function gotoSection(key) {{
    // 'agents' is a plain (always-expanded) container; the rest are collapsible
    // sections identified by their body-<key> element.
    var target;
    if (key === 'agents') {{
        target = document.getElementById('agents');
    }} else {{
        var body = document.getElementById('body-' + key);
        var chevron = document.getElementById('chevron-' + key);
        if (body && body.classList.contains('collapsed')) {{
            body.classList.remove('collapsed');
            if (chevron) chevron.textContent = '▼';
        }}
        target = body;
    }}
    if (target && target.scrollIntoView) {{
        target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }}
}}

// Scroll-spy: highlight the nav chip for the section nearest the top of the
// viewport. Sections may be collapsed (display:none on the body), so we anchor
// on a stable element per key — the section wrapper containing chevron-<key>,
// or the always-present 'agents' container — rather than the collapsible body.
function _spyTarget(key) {{
    if (key === 'agents') return document.getElementById('agents');
    var chevron = document.getElementById('chevron-' + key);
    return chevron ? chevron.closest('.section') : null;
}}

function initScrollSpy() {{
    var chips = Array.prototype.slice.call(document.querySelectorAll('.nav-chip'));
    if (!chips.length) return;
    var entries = chips.map(function (chip) {{
        return {{ chip: chip, el: _spyTarget(chip.getAttribute('data-key')) }};
    }}).filter(function (e) {{ return e.el; }});

    function onScroll() {{
        var marker = 120; // px below the sticky nav
        var current = entries[0];
        for (var i = 0; i < entries.length; i++) {{
            if (entries[i].el.getBoundingClientRect().top <= marker) current = entries[i];
        }}
        chips.forEach(function (c) {{ c.classList.remove('active'); }});
        if (current) current.chip.classList.add('active');
    }}

    window.addEventListener('scroll', onScroll, {{ passive: true }});
    onScroll();
}}

if (document.readyState !== 'loading') initScrollSpy();
else document.addEventListener('DOMContentLoaded', initScrollSpy);

function toggleSection(id) {{
    const body = document.getElementById('body-' + id);
    const chevron = document.getElementById('chevron-' + id);
    if (body.classList.contains('collapsed')) {{
        body.classList.remove('collapsed');
        chevron.textContent = '▼';
    }} else {{
        body.classList.add('collapsed');
        chevron.textContent = '▶';
    }}
}}

function filterTasks() {{
    const q = document.getElementById('taskSearch').value.toLowerCase();
    const typeVal = document.getElementById('typeFilter').value;
    const rows = document.querySelectorAll('#taskTable tr.task-row');
    let visible = 0;
    rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        const cells = row.querySelectorAll('td');
        const taskType = cells[2] ? cells[2].textContent.trim() : '';
        const matchQ = !q || text.includes(q);
        const matchType = !typeVal || taskType === typeVal;
        const show = matchQ && matchType;
        row.dataset.visible = show ? '1' : '0';
        row.style.display = 'none';
        if (show) visible++;
    }});
    document.getElementById('taskCount').textContent = visible + ' of ' + rows.length + ' tasks';
    taskCurrentPage = 1;
    paginateTasks();
}}

const TASK_PAGE_SIZE = 25;
let taskCurrentPage = 1;

function paginateTasks() {{
    const rows = [...document.querySelectorAll('#taskTable tr.task-row')].filter(r => r.dataset.visible !== '0');
    const totalPages = Math.ceil(rows.length / TASK_PAGE_SIZE);
    const start = (taskCurrentPage - 1) * TASK_PAGE_SIZE;
    const end = start + TASK_PAGE_SIZE;

    rows.forEach((row, i) => {{
        row.style.display = (i >= start && i < end) ? '' : 'none';
    }});

    const pag = document.getElementById('pagination');
    if (totalPages <= 1) {{ pag.innerHTML = ''; return; }}
    let html = '';
    if (taskCurrentPage > 1) html += '<a href="#" onclick="taskPage(' + (taskCurrentPage-1) + ');return false;">◀</a> ';
    html += 'Page ' + taskCurrentPage + ' of ' + totalPages;
    if (taskCurrentPage < totalPages) html += ' <a href="#" onclick="taskPage(' + (taskCurrentPage+1) + ');return false;">▶</a>';
    pag.innerHTML = html;
}}

function taskPage(p) {{ taskCurrentPage = p; paginateTasks(); }}

// Populate type filter dropdown from actual task data
(function() {{
    const rows = document.querySelectorAll('#taskTable tr.task-row');
    const types = new Set();
    rows.forEach(row => {{
        const cells = row.querySelectorAll('td');
        if (cells[2]) types.add(cells[2].textContent.trim());
        row.dataset.visible = '1';
    }});
    const tf = document.getElementById('typeFilter');
    if (tf) {{
        [...types].sort().forEach(t => {{
            const o = document.createElement('option');
            o.value = t; o.textContent = t;
            tf.appendChild(o);
        }});
    }}
    document.getElementById('taskCount').textContent = rows.length + ' tasks';
    paginateTasks();
}})();
</script>
</body></html>'''


def _build_audit_json(report_id: str, event: dict, analysis: dict) -> dict:
    """Build the structured JSON audit record for SIEM ingestion."""
    return {
        'schema_version': '2.0',
        'report_id': report_id,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'analysis': analysis,
    }


def _shorten_url(url: str) -> str:
    """Shorten a URL using TinyURL's free API.

    Prevents long presigned URLs from being line-wrapped and broken in email
    clients (RFC 2822 wraps at ~76 chars). TinyURL redirects directly to the
    destination with no interstitial for valid links.

    Falls back to original URL if service is unavailable.

    Args:
        url: Long URL to shorten.

    Returns:
        Shortened URL or original if shortening fails.
    """
    import urllib.request
    import urllib.parse

    try:
        api_url = f"https://tinyurl.com/api-create.php?url={urllib.parse.quote(url, safe='')}"  # nosec B608 — URL construction, not SQL; TinyURL API is opt-in
        req = urllib.request.Request(api_url, method='GET')
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 — TinyURL API, no user-controlled scheme
            short = resp.read().decode('utf-8').strip()
            if short.startswith('http'):
                return short
    except Exception as exc:
        logger.warning("URL shortening failed (using full URL): %s", exc)

    return url


def _send_sns_notification(report_id: str, analysis: dict, credits: dict, s3_key: str) -> None:
    """Send SNS notification with executive summary and report access paths.

    Leads with the console/CLI path (uses recipient's own credentials, no expiry).
    Provides a presigned S3 URL (8-hour expiry, SigV4) as a temporary direct link,
    angle-bracketed to survive plain-text email line-wrapping. Optional URL
    shortening (ENABLE_URL_SHORTENING, default off) applies to the presigned URL.

    Args:
        report_id: Report identifier.
        analysis: Bedrock analysis output.
        credits: Credit consumption data.
        s3_key: S3 key for the HTML report.
    """
    if not SNS_TOPIC_ARN:
        return

    risk_level = _sanitize_enum(analysis.get('risk_level', 'GREEN'), _VALID_RISK_LEVELS, 'GREEN')
    summary = analysis.get('executive_summary', 'Report generated.')
    risk_flags = analysis.get('risk_flags', [])
    recs = analysis.get('recommendations', [])

    # Generate 8-hour presigned URL (SigV4 with regional endpoint)
    from botocore.config import Config
    s3_client = boto3.client(
        's3',
        region_name=REGION,
        config=Config(signature_version='s3v4'),
    )
    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': RESULTS_BUCKET, 'Key': s3_key},
            ExpiresIn=28800,  # 8 hours
        )
        presigned_url = _shorten_url(presigned_url) if ENABLE_URL_SHORTENING else presigned_url
    except Exception as exc:
        logger.warning("Presigned URL generation failed: %s", exc)
        presigned_url = f"s3://{RESULTS_BUCKET}/{s3_key}"

    # Credit consumption one-liner
    alert = credits.get('alert_level', 'NOT_CONFIGURED')
    credit_line = credits.get('summary', '') if alert != 'NOT_CONFIGURED' else ''

    # Build concise email body.
    # Subject leads with the plain-language verdict (matching the in-report
    # verdict banner) so a CISO sees the bottom line in the inbox. Date/time are
    # derived from report_id (audit-YYYYMMDD-HHMMSS) rather than a fresh clock
    # read, so the subject stays consistent with the report ID/body and same-day
    # reports remain distinct via the HH:MM time.
    _verdict_word = {
        'GREEN': 'LOW RISK',
        'YELLOW': 'MODERATE RISK',
        'ORANGE': 'ELEVATED RISK',
        'RED': 'HIGH RISK',
    }.get(risk_level, 'LOW RISK')
    try:
        _dt = datetime.strptime(report_id, 'audit-%Y%m%d-%H%M%S').replace(tzinfo=timezone.utc)
        subject_when = _dt.strftime('%b %d, %Y %H:%M UTC')
    except (ValueError, TypeError):
        subject_when = report_id  # unexpected format — raw id is still unique
    subject = f"[AuditTheAgent] {_verdict_word} — AI Agent Governance — {subject_when}"

    flags_text = ''
    if risk_flags:
        flags_text = '\nRISK FLAGS:\n' + '\n'.join(
            f"  [{f['severity']}] {f['flag']}" for f in risk_flags[:5]
        )

    recs_text = ''
    if recs:
        recs_text = '\nRECOMMENDATIONS (AI-inferred, review with caution):\n' + '\n'.join(
            f"  [{r['priority']}] {r['action']}" for r in recs[:3]
        )

    message = f"""AGENTAUDIT DAILY REPORT — {risk_level}
{'=' * 50}

{summary}
{f'''
CREDIT STATUS: {credit_line}''' if credit_line else ''}
{flags_text}
{recs_text}

{'=' * 50}
VIEW FULL INTERACTIVE DASHBOARD

Recommended (uses your own AWS access, no expiry):
  aws s3 cp s3://{RESULTS_BUCKET}/{s3_key} ./report.html && open report.html

Temporary direct link (valid 8 hours):
  <{presigned_url}>

---
AuditTheAgent — AI Agent Governance for Enterprise
Data sources: CloudTrail, CUR, IAM | Analysis: Amazon Bedrock (Claude)
"""

    try:
        sns = boto3.client('sns', region_name=REGION)
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
        )
        logger.info("SNS notification sent: %s", subject)
    except Exception as exc:
        logger.warning("SNS notification failed: %s", exc)


def _build_findings_csv(findings: list) -> str:
    """Build the reviewable findings CSV for the suppress/accept feedback loop.

    Columns: finding_id, dimension, finding, severity, decision, reason.
    The CISO fills 'decision' (suppress|accept) and 'reason', then re-uploads
    to the review inbox. The feedback Lambda ingests it into suppressions.json.

    finding_id carries an 'f-' prefix so spreadsheet tools treat it as text
    (an all-digit hash would be mangled into scientific notation on round-trip).

    Args:
        findings: Flat list of finding dicts from the compliance stage.

    Returns:
        CSV string (empty template with header if no findings).
    """
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(['finding_id', 'dimension', 'finding', 'severity', 'decision', 'reason'])
    for f in findings:
        writer.writerow([
            f.get('finding_id', ''),
            f.get('dimension', ''),
            f.get('finding', ''),
            f.get('severity', ''),
            '',  # decision — CISO fills: suppress | accept
            '',  # reason — CISO fills
        ])
    return buf.getvalue()


def handler(event: dict, context: Any) -> dict:
    """Lambda entry point — generate interactive HTML dashboard and JSON audit.

    Args:
        event: Step Functions input containing analysis results from all stages.
        context: Lambda context (unused).

    Returns:
        Dict with S3 URLs for the generated report artifacts.
    """
    report_id = f"audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    logger.info("Generating report: %s", report_id)

    # Extract stage outputs
    analysis = event.get('analyze', {}).get('analysis', event.get('analyze', {}))
    trust = event.get('compliance', {})
    enrich = event.get('enrich', {})
    collect = event.get('collect', {})

    # Per-agent cost data (new structure: {devops: {...}, security: {...}})
    # Backward compat: if enrich has 'source' key, it's old flat format
    if 'source' in enrich:
        # Legacy flat format — wrap as devops-only
        per_agent_cost = {'devops': enrich}
    else:
        per_agent_cost = enrich

    # DevOps credits (only agent with ES credit consumption)
    credits = per_agent_cost.get('devops', {}).get('credits', {})

    # Generate HTML
    html = _build_html(report_id, analysis, trust, credits, collect, per_agent_cost)

    # Generate JSON
    audit_json = _build_audit_json(report_id, event, analysis)

    # Upload to S3
    s3 = boto3.client('s3', region_name=REGION)
    prefix = f"agentaudit/{report_id}"

    s3.put_object(
        Bucket=RESULTS_BUCKET,
        Key=f"{prefix}/report.html",
        Body=html.encode('utf-8'),
        ContentType='text/html',
    )

    s3.put_object(
        Bucket=RESULTS_BUCKET,
        Key=f"{prefix}/audit.json",
        Body=json.dumps(audit_json, indent=2, default=str).encode('utf-8'),
        ContentType='application/json',
    )

    # Reviewable findings CSV for the suppress/accept feedback loop (run-scoped key)
    findings = trust.get('findings', [])
    findings_csv = _build_findings_csv(findings)
    s3.put_object(
        Bucket=RESULTS_BUCKET,
        Key=f"{prefix}/findings.csv",
        Body=findings_csv.encode('utf-8'),
        ContentType='text/csv',
    )
    logger.info("findings.csv written: %d findings", len(findings))

    report_url = f"https://{RESULTS_BUCKET}.s3.{REGION}.amazonaws.com/{prefix}/report.html"
    logger.info("Report uploaded: %s", report_url)

    # Send notification with presigned URL
    _send_sns_notification(report_id, analysis, credits, f"{prefix}/report.html")

    return {
        'report_id': report_id,
        'html_url': f"s3://{RESULTS_BUCKET}/{prefix}/report.html",
        'json_url': f"s3://{RESULTS_BUCKET}/{prefix}/audit.json",
        'risk_level': analysis.get('risk_level', 'GREEN'),
    }
