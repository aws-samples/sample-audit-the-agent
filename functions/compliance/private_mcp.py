# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Private MCP detection utilities — now integrated into trust posture assessment.

This module is retained for backward compatibility. The detection logic has been
moved into the main compliance/app.py handler (_assess_visibility_gaps).

Private MCP audit blind spot context:
- Agent tool calls to private MCP servers via VPC Lattice are NOT in CloudTrail
- Only the Agent Journal captures what the agent did via private tools
- Network-level activity is only visible via VPC Flow Logs (if enabled)
- Resources managed by the agent are tagged 'AWSAIDevOpsManaged'

Detection signals:
1. EC2 tags with key 'AWSAIDevOpsManaged' (resource gateways)
2. ENIs tagged 'AWSAIDevOpsManaged' (VPC Lattice endpoints)
3. CloudTrail ListAssociations with filterServiceTypes containing 'mcpserver'
"""

# Detection logic is now in compliance/app.py → _assess_visibility_gaps()
# This file exists for documentation and potential future utility extraction.
