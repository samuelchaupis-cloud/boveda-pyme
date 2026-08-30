import os

import pytest
from botocore.exceptions import ClientError

from boveda.database import Snapshot, init_db
from boveda.storage import abort_multipart_upload, cleanup_in_progress_snapshots


class MockS3Client:
    def __init__(self):
        self.aborted = []
        self.fail_abort = False

    def abort_multipart_upload(self, Bucket, Key, UploadId):
        if self.fail_abort:
            raise ClientError(
                {"Error": {"Code": "NoSuchUpload", "Message": "Not found"}},
                "AbortMultipartUpload",
            )
        self.aborted.append((Bucket, Key, UploadId))


@pytest.fixture
def db_session():
    db_path = "test_storage.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    Session = init_db(db_path)
    session = Session()
    yield session
    session.close()
    Session.kw["bind"].dispose()
    if os.path.exists(db_path):
        os.remove(db_path)


def test_abort_multipart_success():
    client = MockS3Client()
    abort_multipart_upload(client, "my-bucket", "key", "uid-123")
    assert len(client.aborted) == 1
    assert client.aborted[0] == ("my-bucket", "key", "uid-123")


def test_abort_multipart_failure(caplog):
    client = MockS3Client()
    client.fail_abort = True
    abort_multipart_upload(client, "my-bucket", "key", "uid-123")
    assert len(client.aborted) == 0
    assert "abort_multipart_fallido" in caplog.text


def test_cleanup_in_progress_snapshots(db_session):
    snap1 = Snapshot(
        id="snap-stale-1",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="RUNNING",
        multipart_upload_id="up-1",
    )
    snap2 = Snapshot(
        id="snap-stale-2",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="RUNNING",
        multipart_upload_id=None,
    )
    db_session.add(snap1)
    db_session.add(snap2)
    db_session.commit()

    client = MockS3Client()
    cleanup_in_progress_snapshots(db_session, client, "my-bucket")

    # Must have aborted the one with multipart
    assert len(client.aborted) == 1
    assert client.aborted[0][2] == "up-1"

    # Ambos deben estar FAILED
    assert db_session.query(Snapshot).get("snap-stale-1").estado == "FAILED"
    assert db_session.query(Snapshot).get("snap-stale-2").estado == "FAILED"
