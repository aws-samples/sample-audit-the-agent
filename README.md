# AuditTheAgent — Daily Executive Audit Reports for AWS AI Agents

**Auditing the agent, not building another one.**

> What did the agent access? Who authorized it? What did it cost? Is it a risk? Should I be concerned?

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-yellow.svg)](https://opensource.org/licenses/MIT-0) [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/) [![AWS SAM](https://img.shields.io/badge/AWS-SAM-orange.svg)](https://aws.amazon.com/serverless/sam/)

> **⚠️ Important:** This is sample code for demonstration and educational purposes only. It is not intended for production use without thorough review, testing, and hardening by your organization's security and engineering teams. This solution has not been subjected to a full production security review by AWS. Use at your own risk and validate all outputs before making operational decisions.

## Overview

AWS AI agents (**DevOps Agent**, **Security Agent**) operate autonomously. Their actions are bounded by the IAM permissions attached to them, but security leadership still has little day-to-day visibility into what they actually did within those bounds. AuditTheAgent closes that gap with a daily executive report answering five questions:

1. **What did the agent access?** — CloudTrail-sourced, deterministic
2. **Who authorized it?** — Trigger classification (webhook, console, EventBridge, MCP)
3. **What did it cost?** — CUR-first, per-space and per-operation, with credit-burn tracking
4. **Is it a risk?** — Trust Posture (5 dimensions, rules-based)
5. **Should I be concerned?** — AI summary with deterministic guardrails

It's a serverless pipeline (Step Functions + Lambda) that runs on a schedule and delivers an interactive dashboard — no agent of its own, just accountability for the agents you already run.

## Quick Start

### Prerequisites

- AWS SAM CLI installed
- **To build:** either **Docker** running (then `sam build --use-container` —
  recommended, builds against the real Lambda runtime), or a local **Python 3.12
  with pip** (`python3.12 -m ensurepip --upgrade` if pip is missing). `sam build`
  matches the `python3.12` Lambda runtime, so a host without it fails validation.
- AWS account with **DevOps Agent** or **Security Agent** active
- Permission to create IAM roles when you deploy (an admin role, or one with
  `iam:CreateRole`, `iam:GetRole`, `iam:PutRolePolicy`). The stack creates
  least-privilege execution roles for its Lambdas, so a role without IAM
  permissions fails with `AccessDenied`.
- (Recommended) CUR (Cost & Usage Report) in Athena. It's optional — the tool
  runs without it — but CUR unlocks the richest cost insights: per-space and
  per-operation attribution plus credit-burn tracking. The Enterprise Support
  charge behind the credit budget is read from CUR automatically; no separate
  input needed. The CUR parameters are all-or-nothing: provide `CurDatabase`,
  `CurTable`, `CurSourceBucket`, and `AthenaOutputBucket` together to enable CUR,
  or leave them all empty to fall back to Cost Explorer. Partial configuration
  will not work.

### Deploy

Use guided deploy — it prompts for each parameter, handles values with spaces
(e.g. `ScheduleExpression`) correctly, and saves your answers to
`samconfig.toml` for repeatable re-deploys:

```bash
git clone https://github.com/aws-samples/sample-audit-the-agent.git
cd sample-audit-the-agent
sam build
sam deploy --guided
```

> Tip: prefer `--guided` (or editing `samconfig.toml`) over the
> `--parameter-overrides` CLI shorthand — the shorthand splits values on spaces,
> which truncates parameters like `rate(1 day)`.

### Trigger Manually

```bash
aws stepfunctions start-execution \
  --state-machine-arn $(aws cloudformation describe-stacks --stack-name agentaudit \
    --query 'Stacks[0].Outputs[?OutputKey==`StateMachineArn`].OutputValue' --output text) \
  --input '{}'
```

### View Report

```bash
aws s3 ls s3://agentaudit-results-$(aws sts get-caller-identity --query Account --output text)/agentaudit/ --recursive | tail -1
```

## Architecture

![AuditTheAgent Architecture](architecture.png)

**Pipeline:** EventBridge (daily) → Step Functions → 8 Lambda functions → S3 + SNS

**Data Sources (validated, deterministic):**
| Source | What It Provides | Function |
|--------|-----------------|----------|
| CloudTrail | Events, triggers, users, authorization chain | Collect |
| CUR (Athena) | Per-space cost, ES credits, daily burn rate | Enrich |
| IAM | Role trust policies, permission scope, capability level | Trust Posture |
| CloudWatch | ConsumedInvestigationTime metric | Collect |
| Agent API | DescribePrivateConnection (MCP visibility) | Trust Posture |

## Parameters

The tool runs out-of-the-box with all defaults — every parameter is optional.
Guided deploy (`sam deploy --guided`) prompts for each one; the "When to set"
column tells you whether to supply a value or just press Enter.

| Parameter | Default | When to set | Description |
|-----------|---------|-------------|-------------|
| `CurDatabase` | — | **Recommended** | Athena database with the CUR table. Enables per-space cost & credit tracking. |
| `CurTable` | — | **Recommended** | CUR table name in Athena. |
| `CurSourceBucket` | — | **Recommended** | S3 bucket holding CUR Parquet data (Athena reads it from here). |
| `AthenaOutputBucket` | — | **Recommended** | S3 bucket for Athena query results. |
| `NotificationEmail` | — | **Recommended** | Email for report delivery (SNS). Without it, reports land in S3 only. |
| `AgentTypes` | `devops` | Optional | `devops`, `security`, or `both`. |
| `BedrockModelId` | `us.anthropic.claude-sonnet-4-6` | Optional | Bedrock model for the AI summary. |
| `ScheduleExpression` | `rate(1 day)` | Optional | Report frequency (EventBridge schedule). |
| `AthenaWorkgroup` | `primary` | Optional | Athena workgroup for CUR queries. |
| `EnableUrlShortening` | `false` | Optional | Opt-in TinyURL shortening for presigned report URLs (sends URL to a third party). |
| `AgentRoleArns` | — | Optional (auto-discovered) | Additional agent IAM role ARNs to audit. **Adds to** auto-discovery — never narrows it. Leave empty for full auto-discovery. |
| `VendedLogGroup` | — | Optional (auto-discovered) | **DevOps Agent** vended-log group. Leave empty to auto-discover. |
| `MonthlyESCharge` | `0` | Optional (fallback) | Fallback ES charge for credit tracking; auto-derived from CUR when available. |
| `CurCrossAccountRoleArn` | — | Optional (advanced) | IAM role ARN in the CUR account for cross-account queries (see below). |

> Agent space names are resolved automatically from the **DevOps Agent** API — no
> UUID→name mapping needs to be supplied.

**Changing parameters after deployment** is non-destructive — just run `sam deploy` again with updated values. No data loss or resource recreation.

### Cross-Account CUR Setup

Most enterprises keep CUR in the **payer/management account** while agents run in linked accounts. To enable cross-account cost queries, deploy the included `cross-account-role.yaml` in the CUR account — it creates a read-only role the Enrich Lambda assumes.

The two accounts are linked by the **Enrich role ARN**, not by stack naming, so you can name your stacks anything:

**1. Deploy the main stack first** (in the AuditTheAgent account) and note its `EnrichRoleArn` output:
```bash
aws cloudformation describe-stacks --stack-name agentaudit \
  --query 'Stacks[0].Outputs[?OutputKey==`EnrichRoleArn`].OutputValue' --output text
```

**2. Deploy the role in your CUR account,** passing that ARN as `TrustedRoleArn`:
```bash
aws cloudformation deploy \
  --template-file cross-account-role.yaml \
  --stack-name agentaudit-cur-access \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    AgentAuditAccountId=<ACCOUNT_WHERE_AGENTAUDIT_RUNS> \
    TrustedRoleArn=<ENRICH_ROLE_ARN_FROM_STEP_1> \
    CurDatabaseName=<YOUR_CUR_DATABASE> \
    CurSourceBucketName=<YOUR_CUR_S3_BUCKET> \
    AthenaOutputBucketName=<YOUR_ATHENA_RESULTS_BUCKET>
```
Then grab the role ARN it created:
```bash
aws cloudformation describe-stacks --stack-name agentaudit-cur-access \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' --output text
```

**3. Re-deploy the main stack** with `CurCrossAccountRoleArn` set to that ARN (plus `CurDatabase` / `CurTable`):
```bash
sam deploy --guided
```

The Enrich Lambda then assumes this role to query CUR cross-account; leave `CurCrossAccountRoleArn` empty and it queries Athena in its own account instead. The role is read-only (Athena + Glue + CUR bucket).

> `TrustedRoleArn` scopes the trust to that one Enrich role — the most
> least-privilege option and independent of stack names. If you leave
> `TrustedRoleArn` empty, the role falls back to trusting any `agentaudit-*` role
> in the account, which then requires the main stack to be named `agentaudit`.

> Use `--guided` (or edit `samconfig.toml`) for the re-deploy rather than
> `--parameter-overrides` — the shorthand splits on spaces and can truncate other
> parameters like `rate(1 day)`.

## Supported Agents

| Agent | EventSource | Trigger Events | CUR Product Code |
|-------|-------------|----------------|-----------------|
| AWS **DevOps Agent** | `aidevops.amazonaws.com` | CreateBacklogTask, CreateChat | `DevOpsAgent` |
| AWS **Security Agent** | `securityagent.amazonaws.com` | CreatePentest, StartPentestJob | `SecurityAgent` |

## Report Features

![AuditTheAgent Report](demo.gif)

- **KPI Cards** — Risk level, task count, credit %, burn rate at a glance
- **Agent Space Cost Breakdown** — Per-space usage cost across all agents, highest spend first. **Usage Cost** is the actual (unblended) cost; **% of Credit Budget** shows each DevOps space's share of the org-wide **DevOps Agent** credit budget (75% of monthly ES charge, consolidated billing) to surface the biggest credit-burn drivers. Credits are DevOps-Agent-only, so **Security Agent** spaces show **N/A**. A **Tags** column shows each space's own purpose/grouping labels (application, environment, on-call team) from its Agent Space configuration (`aws:*` excluded).
- **Trust Posture** — 5 dimensions with visual risk bars (capability, permissions, visibility, integrations, human approval)
- **Credit Consumption** — Progress bar, burn rate, projection, days until exhaustion
- **Activity Table** — Filterable, paginated (25/page), searchable
- **Authorization Chain** — Who did what, when, from where
- **Risk Flags** — AI-inferred with disclaimer, max 5
- **Recommendations** — AI-inferred with guardrails (Layer 1 prompt + Layer 2 deterministic filter), max 3
- **Email Delivery** — SNS with Presigned S3 link (8hr expiry)

## AI Guardrails

Bedrock generates narrative only — **never decides risk levels or facts**.

| Layer | Mechanism | What It Catches |
|-------|-----------|----------------|
| Prompt | "NEVER suggest org changes, cite data" | Most hallucinations |
| Code | `_validate_recommendations()` | Organizational advice, speculation, normal-ops flags, uncited claims |
| UI | "⚠️ AI-inferred — review with caution" | Reader awareness |

## Testing

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/ -v
```

130 tests covering: trigger classification, CloudTrail parsing, CUR partition logic, credit consumption math, guardrail filters, HTML generation, XSS prevention.

## Troubleshooting

### Build

**`PythonPipBuilder:Validation - Binary validation failed for python`** — the
build host has no `python3.12` matching the Lambda runtime. Install Python 3.12,
or build in a container: `sam build --use-container` (needs Docker).

**`PythonPipBuilder:ResolveDependencies - Failed to find a Python runtime containing pip`** —
Python 3.12 is present but pip isn't wired to it. Bootstrap it with
`python3.12 -m ensurepip --upgrade`, or build in a container.

**`Container creation failed: No such image ...` / `no space left on device`** —
the SAM build image couldn't be pulled/extracted (often low disk on Cloud9).
Free space (`docker system prune -af`, `rm -rf .aws-sam`) or use the host build
(`sam build` after the pip bootstrap above) which pulls no image.

### Deploy

**`AccessDenied` on the function roles** — your deploy identity can't create IAM
roles. Use a role with `iam:CreateRole` / `iam:GetRole` / `iam:PutRolePolicy`
(see Prerequisites).

**A parameter like `rate(1 day)` gets truncated** — you used
`--parameter-overrides`, which splits on spaces. Use `sam deploy --guided` or
edit `samconfig.toml`.

### Runtime

**Where to find logs** — each Lambda logs to `/aws/lambda/<stack>-<Function>-*`,
e.g. for stack `agentaudit`: `agentaudit-EnrichFunction-*`,
`agentaudit-CollectFunction-*`, `agentaudit-ComplianceFunction-*`,
`agentaudit-AnalyzeFunction-*`, `agentaudit-ReportFunction-*` (also Discover,
Aggregate, Feedback). The pipeline itself: Console → Step Functions →
`agentaudit-pipeline` → Executions.

**Report shows "No agent-space cost recorded" / "Credit tracking not configured"** —
usually expected when CUR isn't configured, the account has little agent spend,
or CUR data hasn't landed yet (CUR has ~24h latency). Confirm all four CUR
parameters are set (they're all-or-nothing) and, for cross-account, that the
Enrich role successfully assumed the CUR role (grep the Enrich log for
`cross-account`).

**Cross-account CUR fails with AssumeRole `AccessDenied`** — the CUR role's trust
doesn't allow the Enrich role. Pass the main stack's `EnrichRoleArn` output as
`TrustedRoleArn` when deploying `cross-account-role.yaml` (see Cross-Account CUR
Setup). If the CUR data or Glue database is Lake Formation-managed, also grant
the role access in Lake Formation.

**Bedrock `ValidationException: model not enabled` / `AccessDenied`** — enable the
model in the Bedrock console → Model Access (default
`us.anthropic.claude-sonnet-4-6`).

## Security

- **Read-only** — never modifies customer resources
- **Least privilege** — scoped IAM per function (CloudTrail read, Athena query, S3 write to own bucket)
- **Data stays in-account** — reports in customer's S3, Bedrock runs in customer's account
- **No secrets in code** — all config via SAM parameters / environment variables

## Cost

AuditTheAgent runs serverlessly for **roughly $1–$5/month** on the default daily schedule. The only meaningful cost is a single Amazon Bedrock summary call per run — every other component falls within or near the AWS Free Tier. Prices below are AWS public on-demand pricing (August 2026, `us-east-1`); actual costs vary by region, model, schedule, and data volume.

**Per report run** (default = 1/day → ~30 runs/month):

| Component | Role | Est. per run |
|-----------|------|--------------|
| Amazon Bedrock | 1 Claude Sonnet call for the executive summary | ~$0.03–0.12 |
| AWS Lambda | 8 short functions (512 MB, seconds each) | ~$0.00 (free tier) |
| Step Functions (Standard) | ~8–10 state transitions | ~$0.00 (free tier) |
| Athena | CUR cost queries (only if cost enrichment enabled) | ~$0.00–0.02 |
| S3 / SNS / CloudWatch Logs | Report storage, email, logs | negligible |

**Monthly total: ~$1–$5** (dominated by Bedrock). A brand-new account often sees near-$0 for everything except Bedrock (Bedrock has no perpetual free tier).

**What moves the cost:**
- **Bedrock model** (biggest lever) — the default is Claude Sonnet. Set `BedrockModelId` to a smaller model (e.g. Claude Haiku) to cut LLM cost ~5–10× (total well under $1/month), or a larger model for higher-quality narratives.
- **Schedule frequency** — `ScheduleExpression` default is `rate(1 day)`. Hourly (`rate(1 hour)`) multiplies the Bedrock cost ~24× (~$30–$100/month range).
- **Cost enrichment (CUR/Athena)** — enabling the CUR path adds a small per-scan Athena charge; queries hit partitioned data so this is typically cents/month.

For an estimate specific to your usage, see the [AWS Pricing Calculator](https://calculator.aws/). Once deployed, the tool's own credit-tracking (or Cost Explorer filtered to `agentaudit-*` resources) shows real spend after a few days.

## Project Structure

```
sample-audit-the-agent/
├── functions/
│   ├── discover/        Auto-detect spaces, log groups, roles
│   ├── collect/         CloudTrail events, trigger classification
│   ├── enrich/          CUR/Athena cost, ES credit detection
│   ├── compliance/      Trust Posture (5 dimensions)
│   ├── aggregate/       Merge pipeline data
│   ├── analyze/         Bedrock summary + guardrails
│   ├── report/          HTML dashboard + SNS + S3
│   └── feedback/        Reviewed-CSV ingestion (suppressions)
├── statemachine/        Step Functions ASL definition
├── tests/               130 pytest tests
├── template.yaml        SAM/CloudFormation template
├── cross-account-role.yaml   Cross-account CUR read-only role
└── architecture.png     Architecture diagram
```

## License

This library is licensed under the MIT-0 License. See [LICENSE](LICENSE).
