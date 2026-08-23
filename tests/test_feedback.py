# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for the Feedback function (reviewed CSV -> suppressions.json)."""
import sys, os, json, io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'functions', 'feedback'))
import importlib.util
_spec = importlib.util.spec_from_file_location('feedback_app', os.path.join(os.path.dirname(__file__), '..', 'functions', 'feedback', 'app.py'))
feedback_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(feedback_app)

import pytest
from unittest.mock import MagicMock


class _FakeS3:
    """Minimal in-memory S3 stub for feedback Lambda tests."""
    def __init__(self, objects=None, raise_on_get=None):
        self._objects = objects or {}
        self._raise_on_get = raise_on_get or {}
        self.put_calls = []

        class _Exc(Exception):
            pass
        # mimic boto3 client.exceptions.NoSuchKey
        self.exceptions = MagicMock()
        self.exceptions.NoSuchKey = KeyError

    def get_object(self, Bucket, Key):
        if Key in self._raise_on_get:
            raise self._raise_on_get[Key]
        if Key not in self._objects:
            raise self.exceptions.NoSuchKey(Key)
        return {'Body': io.BytesIO(self._objects[Key].encode('utf-8'))}

    def put_object(self, Bucket, Key, Body, ContentType=None):
        self._objects[Key] = Body.decode('utf-8')
        self.put_calls.append({'Key': Key, 'Body': Body.decode('utf-8')})


def _event(key):
    return {'Records': [{'s3': {'bucket': {'name': 'b'}, 'object': {'key': key}}}]}


CSV_HEADER = 'finding_id,dimension,finding,severity,decision,reason\n'


def _run(monkeypatch, fake, event):
    monkeypatch.setattr(feedback_app.boto3, 'client', lambda *a, **k: fake)
    monkeypatch.setattr(feedback_app, 'RESULTS_BUCKET', 'b')
    return feedback_app.handler(event, None)


class TestFeedbackIngest:

    def test_valid_decisions_merged(self, monkeypatch):
        csv = CSV_HEADER + 'f-abc,Capability,role x,MEDIUM,suppress,auto-created\n'
        fake = _FakeS3()
        fake._objects['agentaudit/config/review-inbox/reviewer1/r.reviewed.csv'] = csv
        out = _run(monkeypatch, fake, _event('agentaudit/config/review-inbox/reviewer1/r.reviewed.csv'))
        assert out['processed'] == 1
        store = json.loads(fake._objects['agentaudit/config/suppressions.json'])
        assert store['suppressions']['f-abc']['decision'] == 'suppress'
        assert store['suppressions']['f-abc']['added_by'] == 'reviewer1'

    def test_invalid_decision_skipped(self, monkeypatch):
        csv = CSV_HEADER + 'f-abc,Capability,role x,MEDIUM,maybe,\n'
        fake = _FakeS3()
        fake._objects['agentaudit/config/review-inbox/x/r.reviewed.csv'] = csv
        out = _run(monkeypatch, fake, _event('agentaudit/config/review-inbox/x/r.reviewed.csv'))
        assert out['processed'] == 0

    def test_merge_not_replace(self, monkeypatch):
        existing = json.dumps({'version': 1, 'suppressions': {'f-old': {'decision': 'accept'}}})
        csv = CSV_HEADER + 'f-new,Permission,x,HIGH,suppress,\n'
        fake = _FakeS3()
        fake._objects['agentaudit/config/suppressions.json'] = existing
        fake._objects['agentaudit/config/review-inbox/x/r.reviewed.csv'] = csv
        _run(monkeypatch, fake, _event('agentaudit/config/review-inbox/x/r.reviewed.csv'))
        store = json.loads(fake._objects['agentaudit/config/suppressions.json'])
        # both old and new present — merge, not replace
        assert 'f-old' in store['suppressions']
        assert 'f-new' in store['suppressions']

    def test_ignores_non_inbox_key(self, monkeypatch):
        fake = _FakeS3()
        out = _run(monkeypatch, fake, _event('agentaudit/20260101-000000/findings.csv'))
        assert out['processed'] == 0
        assert fake.put_calls == []

    def test_ignores_wrong_suffix(self, monkeypatch):
        fake = _FakeS3()
        fake._objects['agentaudit/config/review-inbox/x/notes.txt'] = 'hi'
        out = _run(monkeypatch, fake, _event('agentaudit/config/review-inbox/x/notes.txt'))
        assert out['processed'] == 0

    def test_fail_open_on_corrupt_suppressions(self, monkeypatch):
        # Corrupt existing store must not block new decisions (fail-open = start fresh)
        csv = CSV_HEADER + 'f-abc,Capability,role x,MEDIUM,suppress,\n'
        fake = _FakeS3()
        fake._objects['agentaudit/config/suppressions.json'] = '{not valid json'
        fake._objects['agentaudit/config/review-inbox/x/r.reviewed.csv'] = csv
        out = _run(monkeypatch, fake, _event('agentaudit/config/review-inbox/x/r.reviewed.csv'))
        assert out['processed'] == 1
        store = json.loads(fake._objects['agentaudit/config/suppressions.json'])
        assert 'f-abc' in store['suppressions']
