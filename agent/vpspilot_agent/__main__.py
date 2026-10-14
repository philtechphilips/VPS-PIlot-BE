"""vpspilot-agent command line.

python3 -m vpspilot_agent enroll --url https://pilot.example.com --token ept_...
python3 -m vpspilot_agent run
python3 -m vpspilot_agent status
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from vpspilot_agent import __version__, collectors
from vpspilot_agent.client import ApiError, Client
from vpspilot_agent.config import DEFAULT_PATH, AgentConfig, load, save
from vpspilot_agent.runner import Runner


def cmd_enroll(args: argparse.Namespace) -> int:
    client = Client(args.url)
    try:
        reply = client.post(
            "/agent/v1/enroll", {"token": args.token, "facts": collectors.facts()}
        )
    except ApiError as error:
        print(f"Enrollment failed: {error.message}", file=sys.stderr)
        return 1
    save(
        AgentConfig(
            api_url=args.url.rstrip("/"),
            server_id=reply["server_id"],
            server_name=reply["server_name"],
            agent_token=reply["agent_token"],
            heartbeat_seconds=reply["heartbeat_seconds"],
            metrics_seconds=reply["metrics_seconds"],
        ),
        args.config,
    )
    print(f"Enrolled as {reply['server_name']} ({reply['server_id']})")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout
    )
    try:
        config = load(args.config)
    except (OSError, ValueError, TypeError) as error:
        print(f"Can't read {args.config}: {error}. Enroll first.", file=sys.stderr)
        return 78
    return Runner(config).run()


def cmd_status(args: argparse.Namespace) -> int:
    try:
        config = load(args.config)
        enrolled = {"server": config.server_name, "control_plane": config.api_url}
    except (OSError, ValueError, TypeError):
        enrolled = None
    print(
        json.dumps(
            {"version": __version__, "enrolled": enrolled, "facts": collectors.facts()},
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpspilot-agent")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    enroll = sub.add_parser("enroll", help="Redeem an enrollment token")
    enroll.add_argument("--url", required=True, help="Control plane URL")
    enroll.add_argument("--token", required=True, help="Single-use enrollment token")
    enroll.add_argument("--config", default=DEFAULT_PATH)
    enroll.set_defaults(func=cmd_enroll)

    run = sub.add_parser("run", help="Run the agent loop")
    run.add_argument("--config", default=DEFAULT_PATH)
    run.set_defaults(func=cmd_run)

    status = sub.add_parser("status", help="Show enrollment and host facts")
    status.add_argument("--config", default=DEFAULT_PATH)
    status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
