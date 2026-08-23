# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Vended Logs — readiness check and future-source placeholder.

Current state (Aug 2026): Vended logs only emit TOPOLOGY_CREATION and
TOPOLOGY_REFRESH events. They do NOT contain investigation, chat, webhook,
or error events — those are only in CloudTrail.

Schema fields that exist but are unpopulated today:
  - optional_task_type (INVESTIGATION, CHAT — currently "-")
  - optional_task_id (correlation ID — currently "-")
  - optional_webhook_id (trigger source — currently "-")
  - optional_mcp_endpoint_url (private MCP — currently "-")
  - optional_error_type / optional_error_message (failures — currently "-")

When AWS populates these fields, this module should be expanded to:
1. Query vended logs for investigation/chat lifecycle events
2. Extract webhook trigger payloads
3. Surface private MCP tool call details (audit blind spot)
4. Capture integration failure context

Log group path: /aws/vendedlogs/aidevops/agentspace/APPLICATION_LOGS/{space_uuid}
"""

# This module is intentionally minimal — vended logs are a readiness indicator only.
# The collect/app.py handler calls _check_vended_logs_readiness() directly.
# This file is retained for future expansion when AWS adds richer event types.
