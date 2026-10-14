"""Deployment emails, in the same style as the sign-in emails."""

from html import escape

from app.auth.emails import FONT, MONO, _button, _layout, _note
from app.core import email as mailer


def _details(rows: list[tuple[str, str]]) -> str:
    cells = "".join(
        f'<tr><td style="padding:7px 0;font-family:{FONT};font-size:12px;color:#707070;width:110px;vertical-align:top">{escape(k)}</td>'
        f'<td style="padding:7px 0;font-family:{MONO};font-size:12px;color:#ededed;word-break:break-all">{escape(v)}</td></tr>'
        for k, v in rows
        if v
    )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="margin:22px 0;border-top:1px solid #2e2e2e;border-bottom:1px solid #2e2e2e">'
        f"{cells}</table>"
    )


def send_deployment_email(to: str, d: dict) -> None:
    """`d` is a plain dict (see notifications.service) so this can run after
    the database session is gone."""
    ok = d["status"] == "succeeded"
    app, sha = d["app"], (d["commit_sha"] or "")[:7]
    rows = [
        ("Application", app),
        ("Server", d["server"]),
        ("Source", d["source"]),
        ("Commit", f"{sha} {d['commit_message'] or ''}".strip()),
        ("Built with", d["build_plan"] or ""),
        ("Duration", d["duration"]),
        ("Triggered by", d["created_by"]),
    ]
    if ok:
        subject = f"{app} deployed{f' · {sha}' if sha else ''}"
        chip, heading = "Deployment ready", f"{app} is live"
        intro = "The new version passed its health check and is now serving traffic."
        plain = intro
        if d["address"]:
            rows.insert(2, ("Address", d["address"]))
        note = _note(
            "Want to undo it? Open the app and use Instant Rollback; the previous image is kept on the server."
        )
        button = _button("View deployment", d["url"])
    else:
        subject = f"{app} deployment failed"
        chip, heading = "Deployment failed", f"{app} failed to deploy"
        plain = (d["error"] or "The deployment didn't finish").strip()
        plain += "" if plain.endswith((".", "!", "?")) else "."
        # The agent's own messages often say this already.
        already = any(
            w in plain.lower()
            for w in ("live version", "previous one", "previous version")
        )
        plain += (
            " The previous version is still live."
            if d["had_previous"] and not already
            else ""
        )
        intro = escape(plain)
        note = _note(
            "The build log shows the step that failed. Fix it and redeploy; nothing changed on the server."
        )
        button = _button("View the logs", d["url"])
    html = _layout(
        preheader=f"{heading}. {d['server']} · {d['duration']}",
        chip=chip,
        heading=heading,
        intro=intro if not ok else escape(intro),
        body=f'{_details(rows)}<div style="margin:0 0 22px">{button}</div>{note}',
    )
    text_rows = "\n".join(f"{k}: {v}" for k, v in rows if v)
    text = f"{heading}\n\n{plain}\n\n{text_rows}\n\n{d['url']}\n"
    mailer.send_email(to, subject, html, text)


def send_alert_email(to: str, d: dict) -> None:
    firing = d["firing"]
    if firing:
        subject = f"[{d['severity']}] {d['title']}"
        chip, heading = f"Alert · {d['severity']}", d["title"]
        note = _note(
            "You'll get one more email when it resolves. Acknowledge it in Monitoring to show you're on it."
        )
    else:
        subject = f"Resolved: {d['title']}"
        chip, heading = "Resolved", f"Resolved: {d['title']}"
        note = _note(f"It lasted {d['duration']}.") if d["duration"] else ""
    intro = d["detail"] or ("The condition is back to normal." if not firing else "")
    html = _layout(
        preheader=f"{heading}. {intro}",
        chip=chip,
        heading=heading,
        intro=escape(intro),
        body=f'<div style="margin:24px 0 22px">{_button("Open Monitoring", d["url"])}</div>{note}',
    )
    text = f"{heading}\n\n{intro}\n\n{d['url']}\n"
    mailer.send_email(to, subject, html, text)
