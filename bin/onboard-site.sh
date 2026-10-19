#!/usr/bin/env bash
#
# Creates one site's write-only upload credentials and prints its .env lines.
#
#   bin/onboard-site.sh <site> <host>[,<host>...]
#   bin/onboard-site.sh example example.fi,www.example.fi,www.example.se
#
# The site gets its own service account holding Storage Object Creator on its
# own managed folder only: it can upload, but cannot list, read, overwrite or
# delete anything, its own folder included. Run it as a project owner.

set -euo pipefail

PROJECT=genero-audit-logs
BUCKET=genero-audit-logs

site=${1:?usage: $0 <site> <hosts>}
hosts=${2:?usage: $0 <site> <hosts>}

if [[ ! $site =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
  echo "site must be lowercase letters, digits and dashes: $site" >&2
  exit 1
fi

# Service account IDs are 6–30 characters; long site names get a hash suffix.
account="audit-$site"
if (( ${#account} > 30 )); then
  account="audit-${site:0:17}-$(printf %s "$site" | shasum | cut -c1-6)"
fi
email="$account@$PROJECT.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe "$email" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$account" --project="$PROJECT" \
    --display-name="Audit log uploads: $site"
fi

if ! gcloud storage managed-folders describe "gs://$BUCKET/$site/" >/dev/null 2>&1; then
  gcloud storage managed-folders create "gs://$BUCKET/$site/"
fi

gcloud storage managed-folders add-iam-policy-binding "gs://$BUCKET/$site/" \
  --member="serviceAccount:$email" --role=roles/storage.objectCreator >/dev/null

key=$(gcloud storage hmac create "$email" --project="$PROJECT" --format='value(metadata.accessId,secret)')
access_id=$(cut -f1 <<<"$key")
secret=$(cut -f2 <<<"$key")

cat <<EOF

Add to the live site's .env (production only):

AUDIT_LOG_SITE='$site'
AUDIT_LOG_HOSTS='$hosts'
AUDIT_LOG_ACCESS_ID='$access_id'
AUDIT_LOG_SECRET='$secret'
EOF
