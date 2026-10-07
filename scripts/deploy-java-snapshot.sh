#!/usr/bin/env sh
set -eu

exec mvn --batch-mode clean deploy "$@"
