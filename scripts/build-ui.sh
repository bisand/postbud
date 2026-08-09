#!/bin/sh
# Build the admin UI and refresh the checked-in dist/.
#
# dist/ is committed so the Rust build never needs node: postbud-api
# embeds it with include_dir at compile time. `npm ci` always — a build
# from package-lock.json is reproducible, a build from a warm
# node_modules is whatever was lying around (regnmed's rule).
set -eu
cd "$(dirname "$0")/../ui/admin"

npm ci
rm -rf dist
npm run build

echo
echo "dist/ rebuilt:"
du -sh dist
