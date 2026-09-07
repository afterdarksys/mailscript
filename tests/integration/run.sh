#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
qualification_dir=$(mktemp -d "${TMPDIR:-/tmp}/mailscript-qualification.XXXXXX")
trap 'rm -rf "$qualification_dir"' EXIT
go build -o "$qualification_dir/mailscript" ./cmd/mailscript
for mta in postfix exim sendmail; do
  docker build --build-arg "MTA=$mta" -t "mailscript-mta:$mta" tests/integration/mta
  python3 tests/integration/mta.py --mailscript "$qualification_dir/mailscript" --mta "$mta"
done
docker build -f tests/integration/mta/Dockerfile.qmail -t mailscript-mta:qmail tests/integration/mta
python3 tests/integration/mta.py --mailscript "$qualification_dir/mailscript" --mta qmail
python3 tests/integration/platform.py --mailscript "$qualification_dir/mailscript" --image "${MAILHUB_IMAGE:-mailhub:qualification-2.7}"
