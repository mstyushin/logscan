logscan
=======
> **DISCLAIMER**: This is an educational project, please don't take it seriously.

---

logscan is a Python utility for log file analysis and threat detection.
It parses log files for suspicious artefacts (IP addresses and hashes), submits them to the **Kaspersky Threat Intelligence Portal (OpenTIP)** API for analysis, and generates CSV or JSON reports containing the artefact, its analysis result, and the date of analysis.

---

logscan supports two execution modes:

- **CLI mode** — run a one-off analysis from the command line.
- **Service mode** — run a Telegram bot loop so analyses can be launched and _some_ settings changed remotely.

## Key Features

- Extracts IPv4/IPv6 addresses and MD5/SHA-1/SHA-256 hashes from provided text file.
- Deduplicates artefacts and optionally filters private/reserved IP ranges.
- Looks up each artefact via the Kaspersky OpenTIP API (`/search/hash`, `/search/ip`).
- Handles OpenTIP quota limits (HTTP 403) with automatic backoff/retry.
- Generates CSV or JSON reports with `(artefact, result, date)` fields.
- Can be launched in service mode acting as a Telegram bot for remote operation with an allowed-chat whitelist.

## Requirements

- [uv](https://docs.astral.sh/uv/getting-started/installation/) >= 0.12.5

## Quick Start using uv
```bash
git clone https://github.com/mstyushin/logscan.git
cd logscan
uv sync
cp .env-example .env
vim .env # paste your OpenTIP token
uv run logscan --file sample_logs/sample.log
cat /tmp/reports/*.csv
```

## Build And Install using uv (recommended)
If you don't have `uv`:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Building
```bash
git clone https://github.com/mstyushin/logscan.git
cd logscan
uv sync
uv build
```

### Installing
Unless you want to install package globally, you can create a virtualenv and install it there:

```bash
uv venv --no-project --no-system /tmp/logscan
source /tmp/logscan/bin/activate
uv pip install dist/logscan-$(uv version --short)-py3-none-any.whl
```

Verify that logscan is installed and callable:
```bash
logscan --help
```

## Build And Install using pip
There is no `setup.py` here, so the only option will be using traditional virtualenv (assuming your OS has virtualenv package installed):

```bash
virtualenv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
python src/logscan/__init__.py --help
```

## Getting an OpenTIP API Token

1. Register on the [Kaspersky Threat Intelligence Portal](https://opentip.kaspersky.com).
2. Request an API token in the web interface (see the [Managing an API token](https://opentip.kaspersky.com/Help/Doc_data/ManagingToken.htm) documentation).
3. Export it as `OPENTIP_API_KEY`.

> **Note:** OpenTIP does not support looking up IPv6 addresses (at least without premium subscription which I have no idea how to get at this point), so be prepared for errors if your log contains these.

## Getting a TG-bot Token

1. Find [this](@BotFather) guy in your TG client.
2. Send him `/newbot` command.
3. Choose username for your bot.
4. Export the token he gave you as `TELEGRAM_TOKEN`.

## Configuration

Configuration is handled via environment variables with sensible defaults.
Please note that command-line arguments override environment variables.

| Setting                      | Env Var                       | CLI Arg                 | Default                                 |
|------------------------------|-------------------------------|-------------------------|-----------------------------------------|
| OpenTIP API key              | `OPENTIP_API_KEY`             | `--api-key`             | `""` (required for all modes)           |
| Telegram bot token           | `TELEGRAM_TOKEN`              | —                       | `""` (required for service mode)        |
| Telegram allowed chat IDs    | `TELEGRAM_ALLOWED_CHATS`      | —                       | `""` (all chats if empty)               |
| Analysis endpoint            | `OPENTIP_ENDPOINT`            | `--endpoint`            | `https://opentip.kaspersky.com/api/v1/` |
| Report format                | `LOGSCAN_REPORT_FORMAT`       | `--format`              | `csv`                                   |
| Default report output dir    | `LOGSCAN_REPORT_DIR`          | `--report-dir`          | `./reports`                             |
| OpenTIP backoff interval (s) | `OPENTIP_BACKOFF_INTERVAL`    | —                       | `15`                                    |
| OpenTIP max retries          | `OPENTIP_MAX_RETRIES`         | —                       | `5`                                     |
| Include private IPs          | `LOGSCAN_INCLUDE_PRIVATE_IPS` | `--include-private-ips` | `false`                                 |

See [.env-example](./.env-example) file. Copy it `cp .env-example .env` and adjust with your desired values.

## CLI Mode

### Analyze a log file

```bash
logscan --file /var/log/auth.log --api-key "your-token" --format csv
```

### Analyze with a JSON report in a custom directory

```bash
logscan --file /path/to/access.log --api-key "your-token" --format json --report-dir ./out
```

### Include private IP ranges

```bash
logscan --file /path/to/log.txt --api-key "your-token" --include-private-ips
```

### Prompts for the file when `--file` is omitted

```bash
logscan
```

### Help

```bash
logscan --help
```

## Service Mode (Telegram Bot)

To run the bot loop:

```bash
logscan --service
```

The bot supports the following commands:

| Command                  | Description                                                             |
|--------------------------|-------------------------------------------------------------------------|
| `/start`                 | Greeting and available commands.                                        |
| `/analyze <path>`        | Analyze a log file, generate a report, reply with the summary and path. |
| `/set_format csv\|json`  | Set the report format for subsequent runs.                              |
| `/set_report_dir <path>` | Set the report output directory.                                        |
| `/status`                | Show the current configuration (secrets are never shown).               |

## Example deployment with systemd

1. Create a service account:

   ```bash
   sudo useradd --system --home /opt/logscan --shell /usr/sbin/nologin logscan
   ```

2. Create a virtualenv under `/opt/logscan`:

   ```bash
   sudo mkdir -p /opt/logscan
   sudo cp -r lib main.py requirements.txt /opt/logscan/
   sudo python3 -m venv /opt/logscan/.venv
   sudo /opt/logscan/.venv/bin/pip install -r /opt/logscan/requirements.txt
   ```

3. Add configuration to `/etc/logscan/logscan.env` (mode `600` since we got secrets there):

   ```bash
   sudo mkdir -p /etc/logscan
   sudo tee /etc/logscan/logscan.env >/dev/null <<'EOF'
   OPENTIP_API_KEY=your-opentip-api-token
   TELEGRAM_TOKEN=your-bot-token
   TELEGRAM_ALLOWED_CHATS=123456789
   LOGSCAN_REPORT_DIR=/opt/logscan/reports
   EOF
   sudo chmod 600 /etc/logscan/logscan.env
   sudo mkdir -p /opt/logscan/reports
   sudo chown -R logscan:logscan /opt/logscan
   ```

4. Install the unit file and start the service:

   ```bash
   sudo cp logscan.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now logscan.service
   ```

5. Check status and logs:

   ```bash
   sudo systemctl status logscan.service
   sudo journalctl -u logscan.service -f
   ```

> **Note:** The service account needs read access to any log files you ask it to analyze and write access to the report directory.

## Unit Tests
```bash
uv run pytest
```

## Reports

Each entry contains:

- `artefact` — the IP address or hash that was analyzed.
- `result` — a compact summary of the OpenTIP verdict (e.g. `zone=Red; status=Malware`).
- `date` — ISO-8601 timestamp of the analysis.

The OpenTIP `Zone` values are color-coded threat classifications:
- `Red` (dangerous/malware)
- `Orange` (not trusted, IPs)
- `Yellow` (adware/other)
- `Grey` (no data)
- `Green` (good/no threats).

## TODOs
- [ ] Setup basic development process, define branching strategy, add CI with quality gates with linter, type checker etc.
- [ ] In service mode allow user to send log files for analysis.
- [ ] In service mode send reports as a file in TG chat.
- [ ] In service mode configure schedule for checks.
- [ ] Make a threat-intelligence provider implementation pluggable, i.e. define some interface and refactor out OpenTIP so that other providers (like VirusTotal) can be added easily.
- [ ] Pack everything in container, add `Dockerfile` and example `docker-compose.yml`.
- [ ] Implement packaging with installer, either as a single binary (using Nuitka, for example) or as a native OS packages.
- [ ] Add mocks for OpenTIP API and TG for e2e testing.
- [ ] Implement keyboard in TG-bot interface. 

## License
MIT
