# Local lab

Test agents, deployments and databases on your Mac with Linux VMs that behave
like real VPSes (systemd, apt, their own network). Uses
[Lima](https://lima-vm.io): `brew install lima`.

| VM | OS | Use |
|---|---|---|
| `web-1` | Ubuntu 24.04 | Docker apps, proxy, Docker databases |
| `web-2` | Debian 12 | native systemd apps, local databases |

## Run it

1. In `be/.env`, set the URL agents use to reach the API from inside a VM:

   ```env
   AGENT_API_URL=http://host.lima.internal:8000
   ```

   Restart the API after changing `.env`.

2. Create the VMs (the first run downloads the Ubuntu and Debian images):

   ```bash
   ./lab/lab.sh up
   ```

3. In the dashboard, **Servers → Enroll Server**, name it `web-1`, copy the
   install command, then:

   ```bash
   ./lab/lab.sh enroll web-1 'curl -fsSL http://host.lima.internal:8000/agent/install.sh | sudo bash -s -- --token ept_…'
   ```

   The server shows up online within a few seconds.

## Things to try

- `./lab/lab.sh stop web-2`: the server turns **offline** after ~35 s.
- Revoke the agent in the dashboard: it stops and systemd doesn't restart it
  (`journalctl -u vpspilot-agent` inside the VM explains why).
- `./lab/lab.sh shell web-1` then `sudo apt-get install -y stress-ng && stress-ng --cpu 2 -t 60`
  to watch CPU climb.
- `./lab/lab.sh down` deletes everything.

What still needs a real VPS: public Let's Encrypt certificates, real DNS and
provider firewalls.
