from unittest.mock import AsyncMock, patch

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
def db_session(tmp_path):
    db_path = str(tmp_path / "test_storage.db")
    Session = init_db(db_path)
    session = Session()
    yield session
    session.close()
    Session.kw["bind"].dispose()


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
    assert db_session.get(Snapshot, "snap-stale-1").estado == "FAILED"
    assert db_session.get(Snapshot, "snap-stale-2").estado == "FAILED"


@pytest.mark.asyncio
async def test_upload_to_s3():
    from boveda.storage import upload_to_s3

    mock_client = AsyncMock()

    await upload_to_s3(mock_client, b"payload", "my-bucket", "my-key")

    mock_client.put_object.assert_called_once_with(
        Bucket="my-bucket", Key="my-key", Body=b"payload"
    )


@pytest.mark.asyncio
@patch("aioboto3.Session")
async def test_delete_objects_s3(mock_session_cls):
    from boveda.storage import delete_objects_s3

    mock_client = AsyncMock()
    mock_session_instance = mock_session_cls.return_value
    mock_session_instance.client.return_value.__aenter__.return_value = mock_client

    keys = [f"key-{i}" for i in range(1500)]
    await delete_objects_s3("my-bucket", keys)

    assert mock_client.delete_objects.call_count == 2
    # First batch
    call1_args = mock_client.delete_objects.call_args_list[0][1]
    assert call1_args["Bucket"] == "my-bucket"
    assert len(call1_args["Delete"]["Objects"]) == 1000

    # Second batch
    call2_args = mock_client.delete_objects.call_args_list[1][1]
    assert call2_args["Bucket"] == "my-bucket"
    assert len(call2_args["Delete"]["Objects"]) == 500


@pytest.mark.asyncio
@patch("aioboto3.Session")
async def test_download_from_s3(mock_session_cls):
    from boveda.storage import download_from_s3

    mock_client = AsyncMock()

    # Mocking the response["Body"].read() logic
    mock_body = AsyncMock()
    mock_body.read.return_value = b"downloaded_payload"
    mock_response = {"Body": mock_body}

    mock_client.get_object.return_value = mock_response

    mock_session_instance = mock_session_cls.return_value
    mock_session_instance.client.return_value.__aenter__.return_value = mock_client

    result = await download_from_s3("my-bucket", "my-key")

    assert result == b"downloaded_payload"
    mock_client.get_object.assert_called_once_with(Bucket="my-bucket", Key="my-key")
    mock_body.read.assert_awaited_once()
