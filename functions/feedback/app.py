# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Feedback Lambda — ingests a reviewed findings CSV into suppressions.json.

Closes the suppress/accept feedback loop:
  1. Report emits {run_id}/findings.csv (finding_id + blank decision column)
  2. CISO marks decisions (suppress|accept) + reason, uploads to the review inbox
     (config/review-inbox/*.reviewed.csv)
  3. This Lambda (S3-triggered) parses the reviewed CSV and MERGES decisions into
     config/suppressions.json, keyed by finding_id, with provenance.
  4. The next Compliance run reads suppressions.json and applies it.

Design safeguards:
  - MERGE, never replace — one reviewer's upload can't wipe prior decisions.
  - Provenance recorded (who/when/source key) for audit and to counter the
    "anyone with S3 write can hide findings" risk.
  - Fail-safe: a malformed CSV row is skipped (not fatal); a totally unparseable
    file leaves the existing suppressions.json untouched.
  - Only processes objects under the review-inbox prefix with the .reviewed.csv
    suffix, so it never loops on the pipeline's own generated findings.csv.
"""

import csv
import io
import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get('REGION', 'us-east-1')
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET', '')
SUPPRESSIONS_KEY = 'agentaudit/config/suppressions.json'
INBOX_PREFIX = 'agentaudit/config/review-inbox/'
REVIEWED_SUFFIX = '.reviewed.csv'

VALID_DECISIONS = {'suppress', 'accept'}


def _load_suppressions(s3, bucket: str) -> dict:
    """Load existing suppressions.json. Fail-open: return empty on missing/corrupt.

    Never suppress-on-error — if the store is unreadable we treat it as empty so
    findings stay visible rather than being silently hidden by a corrupt file.
    """
    try:
        resp = s3.get_object(Bucket=bucket, Key=SUPPRESSIONS_KEY)
        data = json.loads(resp['Body'].read().decode('utf-8'))
        if isinstance(data, dict) and isinstance(data.get('suppressions'), dict):
            return data
        logger.warning("suppressions.json has unexpected shape — starting fresh")
    except s3.exceptions.NoSuchKey:
        logger.info("No existing suppressions.json — creating new")
    except Exception as exc:
        logger.warning("Could not read suppressions.json (%s) — starting fresh", exc)
    return {'version': 1, 'suppressions': {}}


def _parse_reviewed_csv(body: str) -> list:
    """Parse a reviewed CSV into decision rows. Malformed rows are skipped.

    Returns a list of {finding_id, decision, reason} for rows with a valid,
    non-blank decision.
    """
    rows = []
    reader = csv.DictReader(io.StringIO(body))
    for raw in reader:
        try:
            fid = (raw.get('finding_id') or '').strip()
            decision = (raw.get('decision') or '').strip().lower()
            reason = (raw.get('reason') or '').strip()
            if not fid or decision not in VALID_DECISIONS:
                continue  # blank/invalid decision — nothing to record
            rows.append({'finding_id': fid, 'decision': decision, 'reason': reason})
        except Exception as exc:
            logger.warning("Skipping malformed CSV row: %s", exc)
            continue
    return rows


def _extract_actor(key: str) -> str:
    """Best-effort provenance from the uploaded object key.

    Convention: config/review-inbox/{actor}/{whatever}.reviewed.csv — the first
    path segment after the inbox prefix is treated as the actor. Falls back to
    'unknown' if not present.
    """
    remainder = key[len(INBOX_PREFIX):] if key.startswith(INBOX_PREFIX) else key
    parts = remainder.split('/')
    return parts[0] if len(parts) > 1 and parts[0] else 'unknown'


def handler(event, context):
    """S3-triggered entry point. Merges a reviewed CSV into suppressions.json."""
    if not RESULTS_BUCKET:
        logger.error("RESULTS_BUCKET not configured")
        return {'processed': 0}

    s3 = boto3.client('s3', region_name=REGION)
    processed = 0

    for record in event.get('Records', []):
        bucket = record.get('s3', {}).get('bucket', {}).get('name', '')
        key = record.get('s3', {}).get('object', {}).get('key', '')

        # Guard: only reviewed CSVs in the inbox — never the pipeline's own output
        if not key.startswith(INBOX_PREFIX) or not key.endswith(REVIEWED_SUFFIX):
            logger.info("Ignoring non-reviewed object: %s", key)
            continue

        try:
            resp = s3.get_object(Bucket=bucket, Key=key)
            body = resp['Body'].read().decode('utf-8')
        except Exception as exc:
            logger.warning("Could not read uploaded CSV %s: %s", key, exc)
            continue

        decisions = _parse_reviewed_csv(body)
        if not decisions:
            logger.info("No valid decisions in %s — nothing to merge", key)
            continue

        store = _load_suppressions(s3, bucket)
        actor = _extract_actor(key)
        now = datetime.now(timezone.utc).isoformat()

        # MERGE (not replace) — keyed by finding_id, with provenance
        for d in decisions:
            store['suppressions'][d['finding_id']] = {
                'decision': d['decision'],
                'reason': d['reason'],
                'added_by': actor,
                'added_at': now,
                'source_key': key,
            }

        s3.put_object(
            Bucket=bucket,
            Key=SUPPRESSIONS_KEY,
            Body=json.dumps(store, indent=2).encode('utf-8'),
            ContentType='application/json',
        )
        processed += len(decisions)
        logger.info("Merged %d decision(s) from %s into suppressions.json (actor=%s)",
                    len(decisions), key, actor)

    return {'processed': processed}
