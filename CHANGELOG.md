# Changelog

All notable changes to NotifyRouter are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Changes in this section are available on the default branch but have not been
promoted to a tagged release or production deployment.

### Changed

- Retain the required PowerShell quality check during automatic reconciliation.

- Refresh repository quality gates, add the approved licence decision metadata, & enforce managed-module drift checks.

### Added

- Modular repository quality gates for Python, PHP, shell, documentation, and
  secret-scanning checks.
- Matching local Git hooks and GitHub Actions workflows so publication checks
  use the same portable secret-detection policy.
- Repository security-policy inheritance and private vulnerability-reporting
  fallback documentation.
- Repository ownership rules through `CODEOWNERS`.
- Dependabot configuration for weekly Python dependency updates.

### Changed

- Updated the repository quality-gate configuration to the modular template.
- Expanded the supported `cryptography` dependency range from `>=45,<47` to
  `>=45,<51`.
- Declared the current development version as `0.5.1` without creating a
  release, tag, or deployment.

## [0.5.0] - 2026-09-14

### Changed

### Added

- Database-backed administrator accounts using the same user, role, and
  permission model as other accounts.
- Initial setup workflow that creates an enabled Administrator account.
- General administration page containing the Site Support User selector and
  global two-factor-authentication policy.
- Validation that requires the Site Support User to be enabled and have a
  valid email address.
- Protection preventing the selected Site Support User from being disabled or
  deleted until a replacement is selected.
- Regression coverage for database-backed setup, authentication, general
  settings, support-user safeguards, and the removed legacy routes.

### Changed

- Replaced the legacy password-only Administrator authentication path with
  normal database-backed sign-in.
- Updated user counts and the user directory to report only real user records.
- Reduced the legacy gateway entry point to the canonical application
  bootstrap.

### Removed

- Legacy Administrator account, recovery bypass, and session-upgrade paths.
- Legacy `admin_hash` configuration.
- Superseded Security administration page; its remaining settings moved to
  General.

### Validation

- PHP 8.4 and PHP 8.5 unit suites passed with 61 assertions each.
- PHP HTTP integration tests passed on PHP 8.4 and PHP 8.5.
- Python regression suite passed with 14 tests.

## [0.4.2] - 2026-09-14

### Changed

### Added

- Physical PHP entry points for the root application, Administration, profile
  image, password recovery, settings, setup, inspection, and webhook routes.
- Document-root HTTP regression tests that exercise the production routing
  layout rather than a catch-all development router.
- Release link in the displayed application version.

### Changed

- Made `/` the canonical Rules & Outputs application route.
- Made `/admin` the canonical Administration route.
- Updated navigation, profile, and administration links for the production
  route layout.

### Fixed

- Corrected production 404 responses caused by relying on nested Apache URL
  rewriting.
- Removed the obsolete root rewrite dependency.

### Validation

- PHP 8.4 and PHP 8.5 unit suites passed with 59 assertions each.
- PHP HTTP integration tests passed on PHP 8.4 and PHP 8.5.
- Python regression suite passed with 13 tests.

## [0.4.1] - 2026-09-14

### Changed

### Added

- Regression coverage for panel sizing, navigation order, profile placement,
  and session authorization refresh.

### Changed

- Moved the profile image into account navigation beside Settings.
- Refreshed existing administrator sessions into the current permission model.

### Fixed

- Restored full-width responsive panels when Semantic UI is loaded.
- Restored Administration access for existing legacy administrator sessions
  without requiring sign-out.

### Validation

- PHP 8.4 and PHP 8.5 unit suites passed with 59 assertions each.
- PHP HTTP integration tests passed on PHP 8.4 and PHP 8.5.
- Python regression suite passed with 11 tests.

## [0.4.0] - 2026-09-14

### Changed

### Added

- Semantic UI administration console with Overview, Users, Roles &
  Permissions, Service Health, Destinations, Security, Email, and Log pages.
- User creation, editing, deletion, enablement, password generation, and
  password-reset invitation workflows.
- Built-in Administrator and User roles with granular permissions for rules,
  templates, events, payload logs, and administration.
- Separate inbound rule matches, outbound message templates, and reusable
  Pushover or email destinations.
- Destination-specific test actions for Pushover and SMTP delivery.
- Configurable Pushover and SMTP service-health checks.
- Global email account, HTML or plain-text mode, common footer, welcome
  template, password-reset template, and per-user template tests.
- Optional enforced TOTP two-factor authentication with enrollment and
  verification flows.
- System audit log covering authentication, password, configuration, webhook,
  and message events.
- Profile email, Gravatar or uploaded profile image, and password-change
  settings.
- SVG favicons for the Python and PHP interfaces.
- Complete PHP unit and HTTP integration test suites.

### Changed

- Adopted Semantic UI across the administration interface.
- Expanded database initialization for users, roles, permissions,
  destinations, outbound templates, reset tokens, and audit records.
- Corrected Python package discovery for reproducible builds.

### Validation

- PHP 8.4 and PHP 8.5 unit suites passed with 58 assertions each.
- PHP HTTP integration tests passed on PHP 8.4 and PHP 8.5.
- Python regression suite passed with 10 tests.

## [0.3.0] - 2026-09-13

This historical milestone was recorded in the repository before formal GitHub
Release publication began.

### Changed

### Added

- Provider-neutral NotifyRouter product name, visual identity, and logo.
- Renamed Python package and environment-variable namespace.

### Changed

- Rebranded CloudHub Signal Gateway as NotifyRouter across Python, PHP,
  container, documentation, and test assets.
- Replaced product-specific webhook configuration names with the
  `NOTIFYROUTER_` namespace.

## [0.2.0] - 2026-09-13

This historical milestone was recorded in the repository before formal GitHub
Release publication began.

### Changed

### Added

- Native PHP application for Apache-compatible hosting.
- Pushover and SMTP settings, availability checks, and user-triggered tests.
- Email fallback when Pushover is unavailable.
- Profile settings with Gravatar or uploaded image support.
- Password recovery through email or Pushover.
- Friendly recent-event and payload-log inspection.
- Integrated event capture and meaningful application logging.
- Actions to clear recent events and the payload log.

### Changed

- Moved the production gateway from a minimal PHP receiver to the full native
  application bootstrap.
- Kept runtime secrets, event data, and generated configuration outside the
  public repository and document root.

## [0.1.0] - 2026-09-13

This historical milestone was recorded in the repository before formal GitHub
Release publication began.

### Changed

### Added

- Initial rules-driven webhook notification gateway.
- Recursive JSON flattening into dotted template variables.
- Exact and wildcard payload-path matching.
- `all` and `any` condition groups with text, numeric, existence, list, and
  regular-expression operators.
- Static-text and variable substitution for Pushover titles and messages,
  including supported HTML formatting.
- Authenticated administration for settings, rules, payload inspection, and
  recent events.
- Compatible `/alarmid.php` and `/webhook` ingress routes.
- Encrypted Pushover credentials at rest.
- One-mebibyte request-body limit, optional webhook token, CSRF protection,
  and secure session-cookie defaults.
- Python reference implementation with automated engine and application tests.
- Brand documentation, container image definition, and example Compose file.
- Native Apache entry points and initial PHP gateway.

[Unreleased]: https://github.com/terryrogers/notifyrouter/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/terryrogers/notifyrouter/releases/tag/v0.5.0
[0.4.2]: https://github.com/terryrogers/notifyrouter/releases/tag/v0.4.2
[0.4.1]: https://github.com/terryrogers/notifyrouter/releases/tag/v0.4.1
[0.4.0]: https://github.com/terryrogers/notifyrouter/releases/tag/v0.4.0
[0.3.0]: https://github.com/terryrogers/notifyrouter/commit/0ee40c557545d353c12c8f64d6020f18fcdef6a1
[0.2.0]: https://github.com/terryrogers/notifyrouter/commit/d98271ed711719258d960484a09b894d0522ba2e
[0.1.0]: https://github.com/terryrogers/notifyrouter/commit/0f48cdfde209d2a8ed1172fe4eb3b4c985e9d8ce
