#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d /tmp/notifyrouter-integration.XXXXXX)
TEST_DIR_PHP=$TEST_DIR
if command -v cygpath >/dev/null 2>&1; then TEST_DIR_PHP=$(cygpath -m "$TEST_DIR"); fi
PORT=${NOTIFYROUTER_TEST_PORT:-18765}
BASE="http://127.0.0.1:$PORT"
COOKIE="$TEST_DIR/cookies.txt"
cleanup() { [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || :; rm -rf -- "$TEST_DIR"; }
trap cleanup EXIT HUP INT TERM

KEY=$(php -r 'echo sodium_bin2base64(str_repeat(chr(2),SODIUM_CRYPTO_SECRETBOX_KEYBYTES),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);')
cat > "$TEST_DIR/config.php" <<EOF
<?php return ['database'=>'$TEST_DIR_PHP/app.sqlite3','master_key'=>'$KEY','webhook_token'=>'integration-webhook','setup_token'=>'integration-setup','event_log'=>'$TEST_DIR_PHP/events.ndjson'];
EOF
export NOTIFYROUTER_CONFIG="$TEST_DIR/config.php"
php -S "127.0.0.1:$PORT" "$ROOT/php/app.php" >"$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
i=0; while ! curl -sS "$BASE/admin" >/dev/null 2>&1; do i=$((i+1)); [ "$i" -lt 30 ] || { cat "$TEST_DIR/server.log"; exit 1; }; sleep 1; done

status() { curl -sS -o "$TEST_DIR/body" -w '%{http_code}' "$@"; }
expect_status() { expected=$1; shift; actual=$(status "$@"); [ "$actual" = "$expected" ] || { echo "Expected HTTP $expected, got $actual"; cat "$TEST_DIR/body"; exit 1; }; }
csrf() { curl -sS -b "$COOKIE" "$BASE/admin" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n 1; }
db_value() { php -r 'define("NOTIFYROUTER_BOOTSTRAP_ONLY",true); require $argv[1]."/php/app.php"; echo db()->query($argv[2])->fetchColumn();' "$ROOT" "$1"; }

expect_status 302 -X POST -c "$COOKIE" -d 'token=integration-setup&password=correct-horse-battery' "$BASE/admin/setup?token=integration-setup"
expect_status 302 -X POST -b "$COOKIE" -c "$COOKIE" -d 'username=admin&password=correct-horse-battery' "$BASE/admin"
expect_status 200 -b "$COOKIE" "$BASE/admin"; grep -Eq '/admin/settings[^<]*|Settings' "$TEST_DIR/body"; grep -q '/admin/administration' "$TEST_DIR/body"; grep -q 'class="nav-avatar"' "$TEST_DIR/body"
TOKEN=$(csrf); [ -n "$TOKEN" ]

expect_status 200 -b "$COOKIE" "$BASE/admin/administration/overview"; grep -q 'Overview' "$TEST_DIR/body"
for section in users roles service-health destinations security email log; do expect_status 200 -b "$COOKIE" "$BASE/admin/administration/$section"; done

expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=save_role' --data-urlencode 'name=Operators' --data-urlencode 'permissions[]=Manage Inbound Rules' --data-urlencode 'permissions[]=View Recent Events' "$BASE/admin"
ROLE_ID=$(db_value "SELECT id FROM roles WHERE name='Operators'"); [ -n "$ROLE_ID" ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=save_user' --data-urlencode 'username=operator' --data-urlencode 'full_name=Test Operator' --data-urlencode 'email=operator@example.test' --data-urlencode "role_id=$ROLE_ID" "$BASE/admin"
expect_status 200 -b "$COOKIE" "$BASE/admin/administration/users"; grep -Eq '<code>[a-f0-9]{16}</code>' "$TEST_DIR/body"
USER_PASSWORD=$(sed -n 's/.*<code>\([a-f0-9]\{16\}\)<\/code>.*/\1/p' "$TEST_DIR/body" | head -n 1)
USER_ID=$(db_value "SELECT id FROM users WHERE username='operator'"); [ -n "$USER_PASSWORD" ]; [ "$(db_value "SELECT enabled FROM users WHERE id=$USER_ID")" = 0 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=save_user' --data-urlencode "id=$USER_ID" --data-urlencode 'username=operator' --data-urlencode 'full_name=Test Operator' --data-urlencode 'email=operator@example.test' --data-urlencode "role_id=$ROLE_ID" --data-urlencode 'enabled=1' "$BASE/admin"
[ "$(db_value "SELECT enabled FROM users WHERE id=$USER_ID")" = 1 ]

expect_status 302 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=logout' "$BASE/admin"
expect_status 302 -X POST -c "$COOKIE" --data-urlencode 'username=operator' --data-urlencode "password=$USER_PASSWORD" "$BASE/admin"
TOKEN=$(csrf); expect_status 403 -b "$COOKIE" "$BASE/admin/administration/overview"; expect_status 200 -b "$COOKIE" "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=profile' --data-urlencode 'profile_email=operator2@example.test' --data-urlencode 'new_password=updated-password-123' "$BASE/admin/settings"
[ "$(db_value "SELECT COUNT(*) FROM users WHERE id=$USER_ID AND email='operator2@example.test'")" = 1 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=start_2fa' "$BASE/admin/settings"
TOTP_SECRET=$(sed -n 's/.*Authenticator Secret<\/strong><code>\([^<]*\)<\/code>.*/\1/p' "$TEST_DIR/body" | head -n 1); [ -n "$TOTP_SECRET" ]
TOTP_CODE=$(php -r 'define("NOTIFYROUTER_BOOTSTRAP_ONLY",true); require $argv[1]."/php/app.php"; $key=base32_decode_secret($argv[2]); $counter=(int)floor(time()/30); $binary=""; for($i=7;$i>=0;$i--)$binary.=chr(($counter>>($i*8))&255); $hash=hash_hmac("sha1",$binary,$key,true); $o=ord($hash[19])&15; $n=((ord($hash[$o])&127)<<24)|((ord($hash[$o+1])&255)<<16)|((ord($hash[$o+2])&255)<<8)|(ord($hash[$o+3])&255); echo str_pad((string)($n%1000000),6,"0",STR_PAD_LEFT);' "$ROOT" "$TOTP_SECRET")
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=confirm_2fa' --data-urlencode "otp=$TOTP_CODE" "$BASE/admin/settings"
[ "$(db_value "SELECT COUNT(*) FROM users WHERE id=$USER_ID AND two_factor_secret IS NOT NULL")" = 1 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=disable_2fa' "$BASE/admin/settings"
[ "$(db_value "SELECT COUNT(*) FROM users WHERE id=$USER_ID AND two_factor_secret IS NULL")" = 1 ]
expect_status 302 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=logout' "$BASE/admin"
expect_status 302 -X POST -c "$COOKIE" --data-urlencode 'username=operator' --data-urlencode 'password=updated-password-123' "$BASE/admin"
TOKEN=$(csrf); expect_status 302 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=logout' "$BASE/admin"
expect_status 302 -X POST -c "$COOKIE" --data-urlencode 'username=admin' --data-urlencode 'password=correct-horse-battery' "$BASE/admin"; TOKEN=$(csrf)

expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=save_destination' --data-urlencode 'name=Disabled Test Destination' --data-urlencode 'description=Integration test' --data-urlencode 'type=pushover' "$BASE/admin"
DEST_ID=$(db_value "SELECT id FROM destinations WHERE name='Disabled Test Destination'")
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=save_template' --data-urlencode 'name=Connected Template' --data-urlencode "destination_id=$DEST_ID" --data-urlencode 'title_template=Event {{ events.0.alert_key }}' --data-urlencode 'message_template=Site {{ events.0.scope.site_id }}' "$BASE/admin"
TEMPLATE_ID=$(db_value "SELECT id FROM outbound_templates WHERE name='Connected Template'")
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=rule' --data-urlencode 'name=Connected Rule' --data-urlencode 'priority=10' --data-urlencode 'match_mode=all' --data-urlencode 'conditions=[{"path":"events.*.alert_key","operator":"equals","value":"CLIENT_CONNECTED"}]' --data-urlencode "template_id=$TEMPLATE_ID" --data-urlencode 'enabled=1' "$BASE/admin"

expect_status 405 "$BASE/webhook"
expect_status 401 -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/webhook"
expect_status 400 -X POST -H 'X-Signal-Gateway-Token: integration-webhook' -H 'Content-Type: application/json' -d 'not-json' "$BASE/webhook"
expect_status 202 -X POST -H 'X-Signal-Gateway-Token: integration-webhook' -H 'Content-Type: application/json' -d '{"events":[{"alert_key":"CLIENT_CONNECTED","scope":{"site_id":"s1"}}]}' "$BASE/webhook"
grep -q 'Connected Rule' "$TEST_DIR/body"; grep -q 'destination:not_available' "$TEST_DIR/body"

expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=service_health' --data-urlencode 'pushover_operational=1' --data-urlencode 'email_operational=1' "$BASE/admin"
[ "$(db_value "SELECT value FROM settings WHERE key='pushover_operational'")" = 0 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=email_global' --data-urlencode 'smtp_host=smtp.example.test' --data-urlencode 'smtp_port=587' --data-urlencode 'smtp_security=starttls' --data-urlencode 'smtp_user=test-user' --data-urlencode 'smtp_from=notify@example.test' --data-urlencode 'smtp_from_name=NotifyRouter' --data-urlencode 'email_message_type=html' --data-urlencode 'email_footer=Footer' --data-urlencode 'welcome_subject=Welcome' --data-urlencode 'welcome_body=Hello {{ full_name }}' --data-urlencode 'reset_subject=Reset' --data-urlencode 'reset_body=Reset {{ reset_link }}' "$BASE/admin"
[ "$(db_value "SELECT value FROM settings WHERE key='welcome_subject'")" = Welcome ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=security' --data-urlencode 'support_email=support@example.test' --data-urlencode 'enforce_2fa=1' "$BASE/admin"
[ "$(db_value "SELECT COALESCE((SELECT value FROM settings WHERE key='enforce_2fa'),'')")" != 1 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=save_user' --data-urlencode "id=$USER_ID" --data-urlencode 'username=operator' --data-urlencode 'full_name=Test Operator' --data-urlencode 'email=operator2@example.test' --data-urlencode "role_id=$ROLE_ID" "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=security' --data-urlencode 'support_email=support@example.test' --data-urlencode 'enforce_2fa=1' "$BASE/admin"; [ "$(db_value "SELECT value FROM settings WHERE key='enforce_2fa'")" = 1 ]

expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=test_pushover' "$BASE/admin"; grep -q 'not_configured' "$TEST_DIR/body"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=email_global' --data-urlencode 'smtp_host=' --data-urlencode 'smtp_from=' "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=test_email' "$BASE/admin"; grep -q 'not_configured' "$TEST_DIR/body"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=test_destination' --data-urlencode "id=$DEST_ID" "$BASE/admin"; grep -q 'not_configured' "$TEST_DIR/body"

expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=clear_events' "$BASE/admin"; [ "$(db_value 'SELECT COUNT(*) FROM events')" = 0 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=clear_log' "$BASE/admin"; [ ! -s "$TEST_DIR/events.ndjson" ]
[ "$(db_value 'SELECT COUNT(*) FROM audit_log')" -ge 10 ]
expect_status 403 -X POST -b "$COOKIE" --data-urlencode 'csrf=wrong' --data-urlencode 'action=clear_events' "$BASE/admin"

expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_template' --data-urlencode "id=$TEMPLATE_ID" "$BASE/admin"; [ "$(db_value "SELECT COUNT(*) FROM outbound_templates WHERE id=$TEMPLATE_ID")" = 1 ]
RULE_ID=$(db_value "SELECT id FROM rules WHERE name='Connected Rule'"); expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_rule' --data-urlencode "id=$RULE_ID" "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_template' --data-urlencode "id=$TEMPLATE_ID" "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_destination' --data-urlencode "id=$DEST_ID" "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_role' --data-urlencode "id=$ROLE_ID" "$BASE/admin"; [ "$(db_value "SELECT COUNT(*) FROM roles WHERE id=$ROLE_ID")" = 1 ]
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_user' --data-urlencode "id=$USER_ID" "$BASE/admin"
expect_status 200 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=delete_role' --data-urlencode "id=$ROLE_ID" "$BASE/admin"; [ "$(db_value "SELECT COUNT(*) FROM roles WHERE id=$ROLE_ID")" = 0 ]
expect_status 302 -X POST -b "$COOKIE" --data-urlencode "csrf=$TOKEN" --data-urlencode 'action=logout' "$BASE/admin"

echo 'PHP HTTP integration tests passed'
