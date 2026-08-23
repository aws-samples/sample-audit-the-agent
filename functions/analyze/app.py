# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Analyze Lambda — uses Bedrock to generate executive summary and risk assessment.

Takes the aggregated audit record (activity, cost, authorization & risk profile) and produces:
- Executive summary (3-4 sentences for CISO consumption)
- Risk flags with severity and actionable detail
- Authorization chain (who did what, when, how)
- Recommendations prioritized by impact

The Bedrock model receives structured JSON and returns structured JSON.
No LLM-generated HTML is used in the final report — all rendering is Python-based.
This prevents prompt injection from affecting report presentation.
"""

import json
import logging
import os
import re

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'us.anthropic.claude-sonnet-4-6')
REGION = os.environ.get('REGION', 'us-east-1')

ANALYSIS_PROMPT = """You are a cloud security analyst generating a daily executive audit report for a CISO.
Your audience is a Security Director or VP who needs to decide: "Is this AI agent safe to keep running in production?"

Analyze the following 24-hour AWS DevOps Agent activity data and respond with ONLY a valid JSON object.
No markdown fencing, no explanation outside the JSON.

Required JSON structure:
{{
  "executive_summary": "3-4 sentence summary: what happened, any concerns, overall assessment",
  "risk_level": "GREEN|YELLOW|RED",
  "risk_flags": [
    {{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "flag": "short title", "detail": "one-line explanation", "action": "what to do"}}
  ],
  "authorization_chain": [
    {{"time": "HH:MM UTC", "who": "human-readable name", "what": "action taken", "how": "trigger method (console/webhook/SDK/MCP)", "space": "agent space name"}}
  ],
  "cost_assessment": "one sentence on whether cost is normal or anomalous",
  "trust_assessment": "one sentence on agent permission posture",
  "recommendations": [
    {{"priority": "HIGH|MEDIUM|LOW", "action": "specific action item", "rationale": "why this matters"}}
  ]
}}

Rules:
- Translate technical identifiers to friendly names (aidevops.amazonaws.com → AWS DevOps Agent)
- If activity is minimal/normal, say so clearly — CISOs appreciate "all clear" signals
- Flag anything unusual: after-hours activity, unknown trigger sources, permission escalation
- risk_level GREEN = normal operations, YELLOW = review recommended, RED = immediate action needed
- Keep executive_summary under 50 words
- Maximum 5 risk_flags, 10 authorization_chain entries, 5 recommendations

CRITICAL GUARDRAILS FOR RECOMMENDATIONS:
- ONLY recommend actions that are DIRECTLY supported by data in the input
- Every recommendation MUST cite a specific data point (permission name, metric value, event count, cost figure)
- NEVER suggest organizational changes (consolidating spaces, changing team structure, reassigning ownership)
- NEVER recommend actions about systems you have no data for (certificate expiry you didn't check, services you didn't scan)
- NEVER speculate about user intent or whether automation is "misconfigured" — you don't know the intended behavior
- If a data point is concerning but you lack context to recommend a specific action, flag it as an observation only
- A wrong recommendation is MORE DANGEROUS than no recommendation — when in doubt, omit it
- Recommendations must be infrastructure-level and actionable by a security/platform engineer (e.g., "scope IAM policy X to resource tag Y")
- Do NOT recommend business process changes, staffing decisions, or workflow consolidation

KNOWN NORMAL BEHAVIORS (do NOT flag these):
- ListAssociations, AuthenticateAccessToken, ListServices, ListAgentSpaces are routine service polling by the agent runtime — high frequency is NORMAL regardless of volume
- UpdateAssociation with integration types (mcpserver, slack, pagerduty, etc.) is normal integration sync
- Read-only events (ListWebhooks, SearchServiceAccessibleResource) are background discovery
- These events should NOT be counted as "activity" or flagged as anomalous

Agent Activity Data:
{audit_data}"""


def _prepare_audit_data_for_prompt(audit_record: dict) -> str:
    """Prepare audit data for the Bedrock prompt, with size limits.

    Strips large fields and caps total size to stay within token limits.

    Args:
        audit_record: Full aggregated audit record.

    Returns:
        JSON string suitable for prompt injection (max ~40K chars).
    """
    # Create a focused subset for the LLM — exclude raw events list
    prompt_data = {
        'period': audit_record.get('period', {}),
        'activity_summary': audit_record.get('activity', {}),
        'tasks': audit_record.get('tasks', {}),
        'triggers': audit_record.get('triggers', {}),
        'cost_summary': _extract_cost_summary(audit_record.get('cost', {})),
        'trust_posture': _extract_trust_summary(audit_record.get('trust_posture', {})),
    }

    result = json.dumps(prompt_data, indent=2, default=str)

    # Cap at 40K chars to stay within model token limits
    if len(result) > 40000:
        result = result[:40000] + '\n... [truncated for token limits]'

    return result


def _extract_cost_summary(cost: dict) -> dict:
    """Extract key cost fields for the prompt (avoid sending full CUR data).

    Handles both legacy flat format and new per-agent format.

    Args:
        cost: Full cost/enrich output (flat or per-agent keyed).

    Returns:
        Condensed cost summary dict with per-agent breakdown.
    """
    # Detect per-agent format vs legacy flat format
    if 'source' in cost:
        # Legacy flat format
        summary = cost.get('summary', {})
        credits = cost.get('credits', {})
        return {
            'source': cost.get('source', 'unavailable'),
            'total_gross_cost': summary.get('gross_cost', summary.get('total_cost', 0)),
            'total_hours': summary.get('total_hours', 0),
            'agent_spaces_active': summary.get('agent_spaces_active', 0),
            'credit_consumption_pct': credits.get('consumption_pct', 0),
            'credit_alert_level': credits.get('alert_level', 'NOT_CONFIGURED'),
        }

    # Per-agent format
    per_agent = {}
    for agent_name, agent_cost in cost.items():
        summary = agent_cost.get('summary', {})
        credits = agent_cost.get('credits', {})
        per_agent[agent_name] = {
            'display_name': agent_cost.get('agent_display_name', agent_name),
            'source': agent_cost.get('source', 'unavailable'),
            'gross_cost': summary.get('gross_cost', summary.get('total_cost', 0)),
            'total_hours': summary.get('total_hours', 0),
            'agent_spaces_active': summary.get('agent_spaces_active', 0),
        }
        if agent_name == 'devops':
            per_agent[agent_name]['credit_consumption_pct'] = credits.get('consumption_pct', 0)
            per_agent[agent_name]['credit_alert_level'] = credits.get('alert_level', 'NOT_CONFIGURED')
            per_agent[agent_name]['credit_budget'] = credits.get('monthly_credit_budget', 0)
            per_agent[agent_name]['credit_days_until_exhaust'] = credits.get('days_until_exhaust', 0)
            per_agent[agent_name]['credit_status'] = credits.get('credit_status', 'NOT_CONFIGURED')

    return {'per_agent': per_agent}


def _extract_trust_summary(trust: dict) -> dict:
    """Extract key authorization & risk fields for the prompt.

    Args:
        trust: Full authorization & risk output.

    Returns:
        Condensed trust summary dict.
    """
    posture = trust.get('trust_posture', {})
    assessments = trust.get('assessments', {})

    return {
        'overall_risk': posture.get('overall_risk', 'UNKNOWN'),
        'risk_flags': posture.get('risk_flags', []),
        'capability_level': assessments.get('capability_level', {}).get('capability_level', ''),
        'permission_risk': assessments.get('permission_scope', {}).get('risk_level', ''),
        'visibility_risk': assessments.get('visibility_gaps', {}).get('risk_level', ''),
        'integration_risk': assessments.get('integration_exposure', {}).get('risk_level', ''),
    }


def _invoke_bedrock(prompt: str) -> dict:
    """Invoke Bedrock model and parse JSON response.

    Args:
        prompt: Complete prompt string.

    Returns:
        Parsed JSON dict from model response, or fallback error dict.
    """
    bedrock = boto3.client('bedrock-runtime', region_name=REGION)

    try:
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType='application/json',
            accept='application/json',
            body=json.dumps({
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': 2500,
                'temperature': 0.1,  # Low temperature for consistent structured output
                'messages': [{'role': 'user', 'content': prompt}],
            }),
        )

        result = json.loads(response['body'].read())
        analysis_text = result.get('content', [{}])[0].get('text', '{}')

        # Parse JSON response
        try:
            return json.loads(analysis_text)
        except json.JSONDecodeError:
            # Try to extract JSON from response if wrapped in text
            json_match = re.search(r'\{[\s\S]*\}', analysis_text)
            if json_match:
                return json.loads(json_match.group())

            logger.warning("Bedrock returned non-JSON response, using as summary")
            return {
                'executive_summary': analysis_text[:500],
                'risk_level': 'YELLOW',
                'risk_flags': [],
                'authorization_chain': [],
                'cost_assessment': 'Unable to assess — model returned unstructured response.',
                'trust_assessment': 'Unable to assess — model returned unstructured response.',
                'recommendations': [{'priority': 'MEDIUM', 'action': 'Review raw audit data manually', 'rationale': 'Automated analysis returned unstructured response.'}],
            }

    except Exception as exc:
        logger.error("Bedrock invocation failed: %s", exc)
        return {
            'executive_summary': f'Automated analysis unavailable ({type(exc).__name__}). Review raw audit data.',
            'risk_level': 'YELLOW',
            'risk_flags': [],
            'authorization_chain': [],
            'cost_assessment': 'Unable to assess — Bedrock invocation failed.',
            'trust_assessment': 'Unable to assess — Bedrock invocation failed.',
            'recommendations': [{'priority': 'HIGH', 'action': 'Review raw audit data manually', 'rationale': f'Bedrock analysis failed: {str(exc)[:100]}'}],
            'error': str(exc)[:200],
        }


# --- Layer 2: Deterministic post-processing guardrails ---
# These strip hallucinated recommendations that the prompt guardrails didn't catch.

# Keywords that indicate organizational/business advice (not infrastructure)
_ORGANIZATIONAL_KEYWORDS = [
    'consolidat', 'reorganiz', 'staffing', 'hire', 'reassign',
    'team structure', 'merge space', 'combine space', 'workflow change',
    'business process', 'personnel', 'headcount',
]

# Keywords that indicate speculation about intent
_SPECULATION_KEYWORDS = [
    'may be misconfigured', 'might be misconfigured', 'appears misconfigured',
    'possibly unintended', 'likely unintended', 'seems unnecessary',
    'consider whether', 'you should evaluate if',
]

# Known normal service behaviors — never flag these as anomalous
_NORMAL_SERVICE_OPS = [
    'listassociations', 'authenticateaccesstoken', 'listservices',
    'listagentspaces', 'listwebhooks', 'searchserviceaccessibleresource',
    'updateassociation', 'polling', 'heartbeat', 'baseline for list',
]


def _validate_recommendations(recommendations: list, audit_record: dict) -> list:
    """Post-process Bedrock recommendations — strip those not backed by data.

    Applies deterministic filters that catch hallucinations the prompt
    guardrails missed. A stripped recommendation never reaches the report.

    Args:
        recommendations: Raw recommendations from Bedrock.
        audit_record: The full audit input data (source of truth).

    Returns:
        Filtered list of validated recommendations (max 3).
    """
    validated = []

    for rec in recommendations:
        action = rec.get('action', '').lower()
        rationale = rec.get('rationale', '').lower()
        combined = action + ' ' + rationale

        # Filter 1: Organizational/business advice
        if any(kw in combined for kw in _ORGANIZATIONAL_KEYWORDS):
            logger.info("Stripped recommendation (organizational): %s", rec.get('action', '')[:80])
            continue

        # Filter 2: Speculation about intent
        if any(kw in combined for kw in _SPECULATION_KEYWORDS):
            logger.info("Stripped recommendation (speculation): %s", rec.get('action', '')[:80])
            continue

        # Filter 3: Flagging normal service operations as anomalous
        if any(op in combined for op in _NORMAL_SERVICE_OPS):
            logger.info("Stripped recommendation (normal service op): %s", rec.get('action', '')[:80])
            continue

        # Filter 4: Must contain at least one verifiable reference
        # (a number, a known IAM permission, or a resource/cost identifier)
        has_number = any(c.isdigit() for c in combined)
        has_permission = any(
            svc in combined for svc in ['ec2:', 'iam:', 's3:', 'lambda:', 'ecs:', 'rds:', 'sts:']
        )
        has_metric = any(word in combined for word in ['$', '%', '/day', 'hours', 'events', 'roles', 'per day'])

        if not (has_number or has_permission or has_metric):
            logger.info("Stripped recommendation (no data citation): %s", rec.get('action', '')[:80])
            continue

        validated.append(rec)

    # Cap at 3 — fewer = higher quality, less noise for leadership
    return validated[:3]


def _validate_risk_flags(risk_flags: list) -> list:
    """Post-process risk flags — strip speculative or organizational ones.

    Args:
        risk_flags: Raw risk flags from Bedrock.

    Returns:
        Filtered list of validated risk flags (max 5).
    """
    validated = []

    for flag in risk_flags:
        detail = flag.get('detail', '').lower()
        flag_text = flag.get('flag', '').lower()
        combined = detail + ' ' + flag_text

        # Strip organizational suggestions disguised as risk flags
        if any(kw in combined for kw in _ORGANIZATIONAL_KEYWORDS):
            logger.info("Stripped risk flag (organizational): %s", flag.get('flag', '')[:80])
            continue

        # Strip pure speculation
        if any(kw in combined for kw in _SPECULATION_KEYWORDS):
            logger.info("Stripped risk flag (speculation): %s", flag.get('flag', '')[:80])
            continue

        # Strip flags about normal service operations
        if any(op in combined for op in _NORMAL_SERVICE_OPS):
            logger.info("Stripped risk flag (normal service op): %s", flag.get('flag', '')[:80])
            continue

        validated.append(flag)

    return validated[:5]


def handler(event: dict, context: object) -> dict:
    """Lambda entry point — analyze aggregated audit data with Bedrock.

    Args:
        event: Dict containing 'aggregate' key with unified audit record.
        context: Lambda context.

    Returns:
        Dict with AI analysis, model metadata, and the original audit record.
    """
    audit_record = event.get('aggregate', {})

    logger.info(
        "Analyzing audit record %s with model %s",
        audit_record.get('report_id', 'unknown'),
        BEDROCK_MODEL_ID,
    )

    # Prepare focused data for the prompt
    audit_data = _prepare_audit_data_for_prompt(audit_record)
    prompt = ANALYSIS_PROMPT.format(audit_data=audit_data)

    # Invoke Bedrock
    analysis = _invoke_bedrock(prompt)

    # --- Layer 2: Post-processing guardrails (deterministic) ---
    analysis['recommendations'] = _validate_recommendations(
        analysis.get('recommendations', []), audit_record
    )
    analysis['risk_flags'] = _validate_risk_flags(
        analysis.get('risk_flags', [])
    )

    logger.info(
        "Analysis complete: risk_level=%s, %d risk_flags, %d recommendations",
        analysis.get('risk_level', 'N/A'),
        len(analysis.get('risk_flags', [])),
        len(analysis.get('recommendations', [])),
    )

    return {
        'analysis': analysis,
        'model_used': BEDROCK_MODEL_ID,
        'audit_record': audit_record,
    }
