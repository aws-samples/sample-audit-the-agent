# Changelog

All notable changes to AuditTheAgent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-06-19

### Added
- Initial release — daily executive audit reports for AWS AI agents
- Step Functions pipeline: Discover → Collect → Enrich → Compliance → Aggregate → Analyze → Report
- CloudTrail two-source collection (LookupEvents + vended logs)
- Role auto-discovery via IAM trust policy scan
- CloudWatch `AWS/AIDevOps` metrics for exact cost attribution
- Private MCP server detection via network interface analysis
- Bedrock-powered executive summary with structured JSON (no LLM HTML injection)
- HTML + JSON output to S3 with SNS notification
- Enterprise Support credits tracking (75% of monthly ES charge)
- Risk level badges and compliance drift detection
- Configurable agent role ARNs, schedule, model, and space names

### Fixed
- CloudWatch Period must be multiple of 60 (was causing pipeline failure)
- CSS overflow fix for executive summary tables
