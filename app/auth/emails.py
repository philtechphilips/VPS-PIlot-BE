"""Email content for authentication flows."""

from html import escape

from app.core import email as mailer
from app.core.config import settings

_BRAND = "VPSPILOT"


def _layout(heading: str, body_html: str) -> str:
    return f"""\
<!doctype html>
<html>
  <body style="margin:0;background:#0a0a0a;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#ededed">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px">
      <tr><td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#1c1c1c;border:1px solid #2a2a2a;border-radius:16px;padding:32px">
          <tr><td style="font-size:18px;letter-spacing:-0.5px"><strong>VPS</strong><span style="font-weight:300">PILOT</span></td></tr>
          <tr><td style="padding-top:24px;font-size:20px;font-weight:600">{escape(heading)}</td></tr>
          <tr><td style="padding-top:12px;font-size:14px;line-height:22px;color:#a1a1a1">{body_html}</td></tr>
        </table>
        <p style="font-size:12px;color:#707070;margin-top:16px">Sent by your self-hosted {_BRAND} control plane.</p>
      </td></tr>
    </table>
  </body>
</html>"""


def send_two_factor_code(to: str, code: str, purpose: str) -> None:
    minutes = settings.two_factor_code_expire_minutes
    if purpose == "setup":
        subject = "Verify your email for VPSPilot"
        intro = "Use this code to verify your email and finish setting up the owner account."
    else:
        subject = f"Your VPSPilot sign-in code: {code}"
        intro = "Use this code to finish signing in."

    html = _layout(
        "Your verification code",
        f"""{escape(intro)}
<div style="margin:24px 0;padding:16px;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:12px;text-align:center;font-family:Menlo,Consolas,monospace;font-size:32px;letter-spacing:10px;color:#ffffff">{escape(code)}</div>
The code expires in {minutes} minutes. If you didn't try to sign in, change your password — someone may know it.""",
    )
    text = (
        f"{intro}\n\nCode: {code}\n\nIt expires in {minutes} minutes. "
        "If you didn't try to sign in, change your password."
    )
    mailer.send_email(to, subject, html, text)


def send_password_reset(to: str, link: str) -> None:
    minutes = settings.password_reset_token_expire_minutes
    html = _layout(
        "Reset your password",
        f"""Someone asked to reset the password for this VPSPilot account.
<div style="margin:24px 0"><a href="{escape(link, quote=True)}" style="display:inline-block;background:#a54ca2;color:#fff;text-decoration:none;padding:12px 20px;border-radius:10px;font-weight:600">Choose a new password</a></div>
The link expires in {minutes} minutes and works once. If it wasn't you, ignore this email.""",
    )
    text = (
        "Someone asked to reset the password for this VPSPilot account.\n\n"
        f"Choose a new password: {link}\n\n"
        f"The link expires in {minutes} minutes. If it wasn't you, ignore this email."
    )
    mailer.send_email(to, "Reset your VPSPilot password", html, text)
