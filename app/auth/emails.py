"""Email content for authentication flows.

Styled to match the dashboard: black canvas, the VPSPILOT logotype, a #1c1c1c
panel, magenta accents. Table layout and inline styles only, so it renders in
Gmail, Outlook and Apple Mail; bgcolor attributes back up CSS backgrounds.
"""

from html import escape

from app.core import email as mailer
from app.core.config import settings

FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "'SF Mono',Menlo,Consolas,'Liberation Mono',monospace"


def _logotype() -> str:
    return (
        f'<span style="font-family:{FONT};font-size:20px;line-height:20px;color:#ededed;letter-spacing:-0.5px">'
        '<strong style="font-weight:700;letter-spacing:-1px">VPS</strong>'
        '<span style="font-weight:300;letter-spacing:0.5px">PILOT</span></span>'
    )


def _chip(label: str) -> str:
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
        f'<td style="background:#2a1a2a;border:1px solid #4a2a49;border-radius:999px;padding:4px 12px;'
        f'font-family:{FONT};font-size:12px;line-height:16px;color:#e3a6e0">{escape(label)}</td>'
        "</tr></table>"
    )


def _code_tiles(code: str) -> str:
    cells = "".join(
        f'<td style="padding:0 4px"><div style="width:44px;height:56px;line-height:56px;text-align:center;'
        f"background:#0d0d0d;border:1px solid #2e2e2e;border-radius:12px;font-family:{MONO};"
        f'font-size:26px;font-weight:600;color:#ffffff">{escape(d)}</div></td>'
        for d in code
    )
    return f'<table role="presentation" cellpadding="0" cellspacing="0" align="center"><tr>{cells}</tr></table>'


def _button(label: str, href: str) -> str:
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
        f'<td bgcolor="#a54ca2" style="border-radius:12px;background:#a54ca2;'
        f'background-image:linear-gradient(180deg,#b45bb1,#a04a9d)">'
        f'<a href="{escape(href, quote=True)}" style="display:inline-block;padding:13px 22px;font-family:{FONT};'
        f'font-size:14px;font-weight:600;color:#ffffff;text-decoration:none">{escape(label)} &rarr;</a>'
        "</td></tr></table>"
    )


def _note(text: str) -> str:
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        f'<td bgcolor="#232323" style="background:#232323;border:1px solid #2e2e2e;border-radius:12px;'
        f'padding:12px 14px;font-family:{FONT};font-size:12px;line-height:18px;color:#a1a1a1">'
        f'<span style="color:#e3a6e0">&#9679;</span>&nbsp; {text}</td>'
        "</tr></table>"
    )


def _layout(*, preheader: str, chip: str, heading: str, intro: str, body: str) -> str:
    return f"""\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="dark">
    <meta name="supported-color-schemes" content="dark">
    <title>{escape(heading)}</title>
  </head>
  <body bgcolor="#000000" style="margin:0;padding:0;background:#000000">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0">{escape(preheader)}</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#000000" style="background:#000000">
      <tr><td align="center" style="padding:40px 16px">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px">
          <tr><td style="padding:0 4px 20px">{_logotype()}</td></tr>
          <tr><td bgcolor="#1c1c1c" style="background:#1c1c1c;border:1px solid #2a2a2a;border-radius:20px;padding:32px 28px">
            {_chip(chip)}
            <h1 style="margin:18px 0 0;font-family:{FONT};font-size:22px;line-height:28px;font-weight:600;letter-spacing:-0.4px;color:#ededed">{escape(heading)}</h1>
            <p style="margin:10px 0 0;font-family:{FONT};font-size:14px;line-height:22px;color:#a1a1a1">{intro}</p>
            {body}
          </td></tr>
          <tr><td style="padding:20px 4px 0;font-family:{FONT};font-size:12px;line-height:18px;color:#707070">
            Sent by your self-hosted VPSPilot control plane at
            <a href="{escape(settings.frontend_url, quote=True)}" style="color:#a1a1a1;text-decoration:underline">{escape(settings.frontend_url)}</a>.
            Nothing here leaves your infrastructure except this email.
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>"""


def send_two_factor_code(to: str, code: str, purpose: str) -> None:
    minutes = settings.two_factor_code_expire_minutes
    if purpose == "setup":
        subject = "Verify your email for VPSPilot"
        chip, heading = "Owner setup", "Verify your email"
        intro = "Enter this code to verify your address and finish creating the owner account."
    else:
        subject = f"Your VPSPilot sign-in code: {code}"
        chip, heading = "Sign-in code", "Finish signing in"
        intro = "Your password was accepted. Enter this code to complete sign-in."

    body = f"""
            <div style="margin:26px 0">{_code_tiles(code)}</div>
            {_note(f"Expires in {minutes} minutes and works once. If this wasn't you, change your password — someone may know it.")}"""
    html = _layout(
        preheader=f"Your code is {code}. It expires in {minutes} minutes.",
        chip=chip,
        heading=heading,
        intro=escape(intro),
        body=body,
    )
    text = (
        f"{intro}\n\nCode: {code}\n\nIt expires in {minutes} minutes. "
        "If you didn't try to sign in, change your password."
    )
    mailer.send_email(to, subject, html, text)


def send_password_reset(to: str, link: str) -> None:
    minutes = settings.password_reset_token_expire_minutes
    body = f"""
            <div style="margin:26px 0 22px">{_button("Choose a new password", link)}</div>
            {_note(f"The link expires in {minutes} minutes and works once. Resetting signs out every device. If you didn't ask for this, ignore this email.")}
            <p style="margin:18px 0 0;font-family:{FONT};font-size:12px;line-height:18px;color:#707070;word-break:break-all">
              Button not working? Paste this into your browser:<br>
              <a href="{escape(link, quote=True)}" style="color:#e3a6e0;text-decoration:none">{escape(link)}</a>
            </p>"""
    html = _layout(
        preheader="Reset the password for your VPSPilot owner account.",
        chip="Password reset",
        heading="Reset your password",
        intro="Someone asked to reset the password for this VPSPilot account.",
        body=body,
    )
    text = (
        "Someone asked to reset the password for this VPSPilot account.\n\n"
        f"Choose a new password: {link}\n\n"
        f"The link expires in {minutes} minutes. If it wasn't you, ignore this email."
    )
    mailer.send_email(to, "Reset your VPSPilot password", html, text)
