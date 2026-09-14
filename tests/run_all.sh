#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d /tmp/notifyrouter-unit.XXXXXX)
trap 'rm -rf -- "$TEST_DIR"' EXIT HUP INT TERM
NOTIFYROUTER_TEST_DIR="$TEST_DIR" php "$ROOT/tests/php_unit.php"
sh "$ROOT/tests/php_integration.sh"
