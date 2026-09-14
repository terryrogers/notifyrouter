# NotifyRouter

![NotifyRouter](notifyrouter/static/logo.png)

**Universal Notification Gateway.** A self-hosted rules engine that accepts arbitrary JSON webhooks, exposes every payload item as a template variable, and routes matched notifications to services such as Pushover and email.

## Capabilities

- Recursively flattens arbitrary JSON into dotted variables such as `events.0.alert_key`.
- Matches exact paths or wildcard paths such as `events.*.alert_key`.
- Supports all/any condition groups and common text, number, existence, list, and regular-expression operators.
- Builds Pushover titles and messages from static text, variables, and Pushover-supported HTML.
- Provides an authenticated `/admin` page for Pushover and SMTP settings, rule management, payload inspection, service health, and friendly event/log review.
- Provides a Semantic UI administration console for users, roles and permissions, service health, destinations, security, global email templates, and the system audit log.
- Separates inbound matching rules, outbound message templates, and reusable Pushover or email destinations.
- Includes built-in Administrator and User roles, optional enforced TOTP two-factor authentication, and auditable configuration changes.
- Supports user-triggered Pushover and email tests, email fallback, profile settings, Gravatar or uploaded avatars, and password recovery through email or Pushover.
- Preserves compatibility with the existing `/alarmid.php` webhook path as well as `/webhook`.
- Encrypts Pushover credentials at rest with a deployment-only Fernet key.

## Quick Start

1. Create a Python 3.11+ virtual environment and install with `pip install -e ".[test]"`.
2. Copy `.env.example` to a deployment-only environment file outside the repository and replace every placeholder.
3. Generate the password hash with `python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(input('Password: ')))"`.
4. Generate the encryption key with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
5. Start with `notifyrouter`; put it behind HTTPS and a trusted reverse proxy.

For a container deployment, use `compose.example.yml` as the Portainer stack basis, keep the real environment file outside the repository, and proxy `/` to `127.0.0.1:8080` over HTTPS.

The `php/` directory is the native Apache/PHP deployment. Its generated configuration and SQLite state live outside the document root in a private state directory; they must never be committed.

Point a webhook source at `https://notify.example.com/webhook?token=YOUR_WEBHOOK_TOKEN` (or the compatible `/alarmid.php` path). The token must live only in the deployment environment, never in source control.

## Rule Example

```json
[{"path":"events.*.alert_key","operator":"equals","value":"CLIENT_CONNECTED"}]
```

Templates use `{{ dotted.path }}` placeholders. Payload-derived values are inserted as text; enabling HTML allows static Pushover HTML in the template without treating payload values as template code.

## Security

- Admin sessions use HTTP-only, same-site, secure cookies by default and CSRF tokens on every state-changing form.
- The inbound webhook can require `NOTIFYROUTER_WEBHOOK_TOKEN` through a header or query parameter.
- Request bodies are limited to 1 MiB.
- `.env`, SQLite databases, virtual environments, caches, and bytecode are excluded from Git.
- No live credentials, controller addresses, private payloads, or operational logs belong in this public repository.

## Testing

Run the complete PHP production-path suite on a host with PHP, SQLite, Sodium, cURL, and the `curl` command:

```sh
sh tests/run_all.sh
```

The suite uses disposable directories under `/tmp`, performs core unit tests and HTTP integration tests, and removes its test database, configuration, session cookies, and server process when finished. A successful full pass is required before deployment or publication.

The Python reference implementation retains its separate test suite:

```sh
python -m pytest
```

## Status

Version `0.4.1` corrects the Semantic UI panel layout, places the profile image in account navigation, and upgrades existing administrator sessions to the current permission model. It retains the administration console, role-based access control, reusable destinations and outbound templates, service-health configuration, global email templates, audit logging, optional TOTP two-factor authentication, favicons, and the complete PHP release test suite. Production secrets and runtime event data remain outside the public repository.
