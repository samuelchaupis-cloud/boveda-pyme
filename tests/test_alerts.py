import os
from unittest.mock import patch

import pytest

from boveda.alerts import send_webhook_alert


@pytest.mark.asyncio
async def test_webhook_disabled():
    if "BOVEDA_WEBHOOK_URL" in os.environ:
        del os.environ["BOVEDA_WEBHOOK_URL"]

    # Solo debe retornar y no lanzar error
    await send_webhook_alert("snap-1", "COMPLETED")


@pytest.mark.asyncio
async def test_webhook_enabled():
    os.environ["BOVEDA_WEBHOOK_URL"] = "http://dummy-webhook"

    with patch("aiohttp.ClientSession.post") as mock_post:
        # Configurar el mock asíncrono del context manager
        mock_post.return_value.__aenter__.return_value.status = 200

        await send_webhook_alert("snap-2", "FAILED", "Error simulado")

        mock_post.assert_called_once()
        _args, kwargs = mock_post.call_args
        assert kwargs["json"]["status"] == "FAILED"
        assert kwargs["json"]["error_detail"] == "Error simulado"
        assert kwargs["json"]["snapshot_id"] == "snap-2"

    del os.environ["BOVEDA_WEBHOOK_URL"]
