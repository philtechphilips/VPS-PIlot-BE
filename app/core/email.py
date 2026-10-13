"""Transactional email through the Resend HTTP API."""

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

RESEND_URL = "https://api.resend.com/emails"


class EmailDeliveryError(Exception):
    """Raised when the email provider rejects or fails to accept a message."""


def send_email(to: str, subject: str, html: str, text: str) -> None:
    """Send one email. Raises EmailDeliveryError if Resend doesn't accept it."""
    recipient = to
    if settings.email_override_to:
        recipient = settings.email_override_to
        subject = f"{subject} [to: {to}]"

    if not settings.resend_api_key:
        # Development fallback: no provider configured, so log the message.
        logger.warning(
            "RESEND_API_KEY is not set; email not sent.\nTo: %s\nSubject: %s\n\n%s",
            recipient,
            subject,
            text,
        )
        return

    try:
        response = httpx.post(
            RESEND_URL,
            headers={"Authorization": f"Bearer {settings.resend_api_key}"},
            json={
                "from": settings.email_from,
                "to": [recipient],
                "subject": subject,
                "html": html,
                "text": text,
            },
            timeout=10,
        )
    except httpx.HTTPError as error:
        logger.error("Resend request failed: %s", error)
        raise EmailDeliveryError("Email provider unreachable") from error

    if response.status_code >= 400:
        # Resend returns a JSON body with a "message"; never log the API key.
        logger.error(
            "Resend rejected email (%s): %s", response.status_code, response.text
        )
        raise EmailDeliveryError("Email provider rejected the message")
