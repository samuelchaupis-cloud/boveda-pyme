import logging
import os

import aiohttp

log = logging.getLogger(__name__)


async def send_webhook_alert(
    snapshot_id: str, status: str, error_detail: str | None = None
):
    webhook_url = os.environ.get("BOVEDA_WEBHOOK_URL")
    if not webhook_url:
        log.info(
            f"Webhooks deshabilitados. Estado del snapshot {snapshot_id}: {status}"
        )
        return

    payload = {
        "text": f"Backup {snapshot_id} finalizado con estado: {status}",
        "snapshot_id": snapshot_id,
        "status": status,
    }
    if error_detail:
        payload["error_detail"] = error_detail

    try:
        async with (
            aiohttp.ClientSession() as session,
            session.post(
                webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5.0)
            ) as resp,
        ):
            if resp.status >= 400:
                log.warning(f"Error enviando webhook: HTTP {resp.status}")
    except Exception as e:
        log.warning(f"Excepción al enviar webhook: {e}")
