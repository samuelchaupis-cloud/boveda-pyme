import logging

from botocore.exceptions import ClientError, EndpointConnectionError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_random,
)

from boveda.database import Snapshot

log = logging.getLogger(__name__)


def abort_multipart_upload(s3_client, bucket: str, key: str, upload_id: str):
    """Cancela un upload multipart y libera los chunks de S3."""
    try:
        s3_client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        log.info(f"multipart_abortado bucket={bucket} key={key} upload_id={upload_id}")
    except ClientError as e:
        log.error(f"abort_multipart_fallido error={e} upload_id={upload_id}")


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=1, max=120) + wait_random(0, 5),
    retry=retry_if_exception_type(
        (ClientError, EndpointConnectionError, ConnectionError)
    ),
    reraise=True,
)
def upload_part(
    s3_client, bucket: str, key: str, upload_id: str, part_number: int, body: bytes
) -> dict:
    """Sube un part con reintentos exponenciales + jitter."""
    return s3_client.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=part_number, Body=body
    )


def cleanup_in_progress_snapshots(session, s3_client, bucket: str):
    """Al arrancar, limpia snapshots que quedaron en estado RUNNING."""
    stale = session.query(Snapshot).filter(Snapshot.estado == "RUNNING").all()
    for snap in stale:
        log.warning(f"snapshot_huerfano_detectado snapshot_id={snap.id}")
        if snap.multipart_upload_id:
            # We assume the storage key prefix for multipart is known, e.g. snapshots/{snap.id}/data
            storage_key = f"snapshots/{snap.id}/data"
            abort_multipart_upload(
                s3_client, bucket, storage_key, snap.multipart_upload_id
            )
        snap.estado = "FAILED"
        snap.error_detail = "Proceso interrumpido abruptamente (crash/OOM kill previo)"
    session.commit()
