#!/bin/bash

set -e

echo "Building and uploading asset bundles..."
deno task build

echo "Uploading asset bundles..."
wrangler r2 object put silverbullet/dist/client_asset_bundle.json --file dist/client_asset_bundle.json --remote
wrangler r2 object put silverbullet/dist/plug_asset_bundle.json --file dist/plug_asset_bundle.json --remote

echo "Generating asset bundle indices..."
jq 'map_values({mtime: .mtime, content_type: (.data | split(";")[0] | split(":")[1])})' dist/client_asset_bundle.json >dist/client_asset_index.json
jq 'map_values({mtime: .mtime, content_type: (.data | split(";")[0] | split(":")[1])})' dist/plug_asset_bundle.json >dist/plug_asset_index.json

echo "Building and deploying worker..."
wrangler deploy

echo "Deployment completed successfully!"
