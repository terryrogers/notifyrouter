# CloudHub Signal Gateway

![CloudHub Signal Gateway](signal_gateway/static/logo.png)

**Turn Events Into Action.** A self-hosted rules gateway that accepts UniFi Network Alarm Manager webhooks, exposes every JSON item as a template variable, and sends matched messages to Pushover.

## Capabilities

- Recursively flattens arbitrary JSON into dotted variables such as `events.0.alert_key`.
- Matches exact paths or wildcard paths such as `events.*.alert_key`.
- Supports all/any condition groups and common text, number, existence, list, and regular-expression operators.
- Builds Pushover titles and messages from static text, variables, and Pushover-supported HTML.
- Provides an authenticated `/admin` page for settings, rule management, payload inspection, and recent event status.
- Preserves compatibility with the existing `/alarmid.php` webhook path as well as `/webhook`.
- Encrypts Pushover credentials at rest with a deployment-only Fernet key.

## Quick Start

1. Create a Python 3.11+ virtual environment and install with `pip install -e ".[test]"`.
2. Copy `.env.example` to a deployment-only environment file outside the repository and replace every placeholder.
3. Generate the password hash with `python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(input('Password: ')))"`.
4. Generate the encryption key with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
5. Start with `signal-gateway`; put it behind HTTPS and a trusted reverse proxy.

Point UniFi at `https://alarm.example.com/webhook?token=YOUR_WEBHOOK_TOKEN` (or the compatible `/alarmid.php` path). The token must live only in the deployment environment, never in source control.

## Rule Example

```json
[{"path":"events.*.alert_key","operator":"equals","value":"CLIENT_CONNECTED"}]
```

Templates use `{{ dotted.path }}` placeholders. Payload-derived values are inserted as text; enabling HTML allows static Pushover HTML in the template without treating payload values as template code.

## Security

- Admin sessions use HTTP-only, same-site, secure cookies by default and CSRF tokens on every state-changing form.
- The inbound webhook can require `CSG_WEBHOOK_TOKEN` through a header or query parameter.
- Request bodies are limited to 1 MiB.
- `.env`, SQLite databases, virtual environments, caches, and bytecode are excluded from Git.
- No live credentials, controller addresses, private payloads, or operational logs belong in this public repository.

## Status

Version `0.1.0` is an initial tested implementation. Production deployment, reverse-proxy configuration, persistent storage, backups, and end-to-end Pushover delivery validation are environment-specific steps.

