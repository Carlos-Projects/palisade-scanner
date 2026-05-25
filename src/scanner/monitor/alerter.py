import json
import logging

import httpx

from scanner.monitor.store import MonitorStore

logger = logging.getLogger(__name__)


class Alerter:
    """Dispatches alerts via webhook, Slack, email, or stdout.

    Reads delivery configuration from the monitored URL's settings.
    """

    def __init__(self, store: MonitorStore):
        self.store = store
        self._http = httpx.AsyncClient(timeout=10)

    async def dispatch(self, alert: dict):
        url_id = alert["url_id"]
        entry = self.store.get_url(url_id)
        if not entry:
            return

        payload = {
            "alert_id": alert["id"],
            "alert_type": alert["alert_type"],
            "severity": alert["severity"],
            "message": alert["message"],
            "url": entry["url"],
            "label": entry.get("label", ""),
            "timestamp": alert["created_at"],
        }

        webhook = entry.get("alert_webhook") or ""
        slack = entry.get("alert_slack") or ""

        if webhook:
            await self._send_webhook(webhook, payload)

        if slack:
            await self._send_slack(slack, payload)

        logger.info(f"Alert {alert['id']} dispatched: {alert['message'][:100]}")
        self.store.mark_alert_delivered(alert["id"])

    async def _send_webhook(self, url: str, payload: dict):
        try:
            resp = await self._http.post(url, json=payload)
            resp.raise_for_status()
        except Exception as e:
            logger.warning(f"Webhook delivery failed: {e}")

    async def _send_slack(self, webhook_url: str, payload: dict):
        try:
            resp = await self._http.post(webhook_url, json={
                "text": (
                    f"*Prompt Injection Scanner Alert*\n"
                    f"*Type:* {payload['alert_type']}\n"
                    f"*Severity:* {payload['severity']}\n"
                    f"*URL:* {payload['url']}\n"
                    f"*Message:* {payload['message']}"
                ),
            })
            resp.raise_for_status()
        except Exception as e:
            logger.warning(f"Slack delivery failed: {e}")

    async def close(self):
        await self._http.aclose()
