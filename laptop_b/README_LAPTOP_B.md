# Laptop B: One-command IDS/IPS lab demo

Laptop B is a demo client for **your authorized Laptop A lab system**. Its
launcher checks service readiness, asks you to authenticate, submits the
application's built-in synthetic scenarios, and checks whether expected alerts
appear through the authenticated Alerts API.

The scenarios insert synthetic data through the application API. They do not
send exploit packets to a network service, scan devices, flood a host, or
attempt to compromise a system. Some detections can create alerts and
temporary database block records for documentation-only test IP addresses.
Run only against your own lab and review the confirmation prompt first.

## Prepare Laptop A

1. Start Docker Desktop and the IDS/IPS stack.
2. For host packet capture/firewall integration on Windows, run
   `run_all.bat` from an elevated PowerShell and keep the packet adapter
   running. A healthy API alone does not mean the host adapter is running.
3. Keep Laptop A and Laptop B on the same trusted private network. Find
   Laptop A's current Wi-Fi IPv4 address with `ipconfig`; for example,
   `10.17.31.79`.
4. Permit inbound TCP 8443 on Laptop A's trusted/private firewall profile.
   Never expose the dashboard directly to the public internet.
5. On Laptop A, open `https://localhost:8443` and confirm the dashboard works.

The API is exposed to the LAN through the HTTPS reverse proxy. PostgreSQL,
MongoDB, and Redis are not published as LAN services.

## Install / run on Arch Linux

Python 3 is the only runtime dependency; `run_demo.py` uses only Python's
standard library. From the copied `laptop_b` folder:

```bash
sudo pacman -S --needed python
chmod +x single_click_attack.sh
./single_click_attack.sh --target https://LAPTOP_A_IP:8443 --allow-self-signed
```

Replace `LAPTOP_A_IP` with Laptop A's real Wi-Fi IPv4 address. For example:

```bash
./single_click_attack.sh --target https://10.17.31.79:8443 --allow-self-signed
```

Do **not** run the demo with `sudo`. `--allow-self-signed` disables TLS
certificate verification; use it only on an isolated, trusted lab network.
For normal verification, securely copy Laptop A's public
`nginx/ssl/self-signed.crt` into this folder and run:

```bash
./single_click_attack.sh --target https://LAPTOP_A_IP:8443 --ca-cert ./self-signed.crt
```

The certificate file is public; do not copy or share `self-signed.key`.

The launcher is also usable without arguments: it asks for Laptop A's URL,
then gives an error with the required certificate options if trust has not
been configured. The health-only check does not require credentials:

```bash
./single_click_attack.sh --target https://LAPTOP_A_IP:8443 --allow-self-signed --health-only
```

## Windows Laptop B

From Command Prompt:

```cmd
single_click_attack.bat --target https://LAPTOP_A_IP:8443 --allow-self-signed
```

To pass a trusted certificate instead:

```cmd
single_click_attack.bat --target https://LAPTOP_A_IP:8443 --ca-cert self-signed.crt
```

Python 3 is required. No package installation with pip is needed.

## What the one-command demo does

1. Checks that the React dashboard returns its expected page.
2. Checks `/health` and displays PostgreSQL, MongoDB, and Redis readiness.
3. Checks the read-only PostgreSQL-backed statistics endpoint.
4. Requests a username (defaults to `admin`) and securely prompts for the
   password without echoing it to the terminal.
5. Requires confirmation before sending synthetic test events.
6. Runs the six scenarios in order:

   | Scenario | Synthetic event | Expected database result |
   |----------|-----------------|--------------------------|
   | `benign` | Ordinary sample TCP/UDP records | No alert expected |
   | `sqli` | SQL-injection signature sample | DPI signature alert |
   | `log4shell` | JNDI-pattern signature sample | DPI signature alert |
   | `portscan` | 15 synthetic TCP destination ports | Correlation alert |
   | `sshbrute` | 5 synthetic SSH SYN attempts | Correlation alert |
   | `canary` | Reads the database canary view | Critical canary alert |

7. Queries the authenticated Alerts API to check whether a new expected alert
   appeared, then prints a per-scenario result.

The dashboard's **Alert Feed** is the place to show generated alerts. Open it
before the demo for a live presentation; otherwise reload it after the run.
Some alert events may arrive through Socket.IO, but the persisted alert list
and database are the record to verify. A `PASS` from the demo means an alert
was found through the API; it does not prove live packet detection.

The `portscan` and `sshbrute` labels describe synthetic database scenarios.
They do not transmit a scan or login attempts to Laptop A or another host.
The test source IPs are reserved documentation addresses (198.51.100.0/24
and 192.0.2.0/24). Rules that take a block action can create temporary block
records/firewall entries for those reserved addresses in this isolated lab.
They are not Laptop B's real IP.

## Login and password

The username is `admin`. On Laptop A, check the project-root `.env` for
`ADMIN_LOGIN_PASSWORD`. That value is current only if it matches the existing
database account; editing `.env` alone does not reset an existing user's
password. Never send credentials to Laptop B by chat or commit them into this
folder.

## Capture versus simulation

The demo scenarios above go through the authenticated API and insert rows with
`capture_source = 'simulation'`. They are intended to exercise SQL-side
signatures/correlation and produce dashboard alerts. They do not test physical
packet capture or prove the Windows adapter observes Laptop B's network
traffic.

To create ordinary traffic from Laptop B to Laptop A and check live capture:

```bash
curl -k -sS https://LAPTOP_A_IP:8443/health
ping -c 4 LAPTOP_A_IP
```

`curl -k` is only for the trusted lab's self-signed certificate. On Laptop A,
inspect traffic sent by Laptop B using its actual LAN IP:

```powershell
docker compose exec -T postgres psql -U idsips -d idsips -c "SELECT created_at, src_ip, dst_ip, protocol, src_port, dst_port, capture_source FROM ingress_packets WHERE created_at >= NOW() - INTERVAL '10 minutes' AND (src_ip = 'LAPTOP_B_IP' OR dst_ip = 'LAPTOP_B_IP') ORDER BY id DESC LIMIT 30;"
```

Replace `LAPTOP_B_IP` with the address shown on Arch by:

```bash
ip -4 -o addr show scope global
```

Windows host raw-socket capture is IPv4-only and may not see traffic forwarded
through every Wi-Fi driver, virtual adapter, or Docker networking path. A
successful HTTPS response does not itself prove the packet adapter recorded
the connection. If capture is missing, check that the adapter window remains
open and inspect its errors.

## `224.0.0.251/32:5353` explained

`224.0.0.251` is the IPv4 multicast group used by mDNS (multicast DNS), usually
on UDP port 5353. Devices use it for local-name/service discovery. It is not
the mobile hotspot gateway and is not Laptop B's unicast IP. `/32` is the
host-sized network mask displayed with an individual IPv4 address; it does not
mean the hotspot has assigned that address to the phone.

On Laptop A, the hotspot gateway shown by `ipconfig` is typically the default
gateway address (in this lab it was `10.17.31.83`), while Laptop A itself was
`10.17.31.79` and Laptop B was `10.17.31.137` at the time checked. These
addresses can change when devices reconnect to a hotspot.

## Troubleshooting

- **Connection refused / timeout:** confirm Laptop A is online, the HTTPS
  gateway is running, both devices use the same trusted LAN, and TCP 8443 is
  allowed on Laptop A's private firewall profile.
- **TLS certificate error:** use the copied public certificate with `--ca-cert`
  or, only for this trusted lab, explicitly pass `--allow-self-signed`.
- **401 Invalid credentials:** use the current database password. The
  `ADMIN_LOGIN_PASSWORD` value in Laptop A's `.env` is accurate only if it was
  synchronized during the last password reset.
- **Packets submitted but no alert:** check that the corresponding rule or
  signature is enabled in the database, then inspect API/database logs on
  Laptop A. A submitted scenario is not counted as an alert detection unless
  a new matching alert is found.
- **Health passes but live capture is empty:** Windows raw capture can miss
  the traffic path; inspect the adapter output. Database simulation success
  and packet-capture visibility are separate checks.
- **Stop the demo:** it exits after the scenarios. On Laptop A, stop services
  with `docker compose down` when appropriate; this keeps database volumes.
  Do not use `docker compose down -v` unless you intend to delete the database.
