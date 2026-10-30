# Audit Log

Ships Kinsta access logs and per-request user identity to write-only Google
Cloud Storage, so that after an incident we can show which accounts and
credentials were used, and from where.

- **Access logs:** every hour, rotated `access.log-*` files from Kinsta's
  `logs/` directory are redacted (query-string credentials such as
  `consumer_secret` and `key`), gzipped and uploaded once each.
- **Identity:** for each signed-in request to wp-admin, REST, XML-RPC,
  admin-post, wp-login and My Account, plus any request authenticated by an
  application password or WooCommerce API key, one record with the user, the
  credential (cookie session hash, application password UUID or API key ID),
  the POST action and IDs, and REST sub-requests.
- **Events:** logins, auth cookies issued, failed logins, logouts, password
  resets, application passwords created, used, rejected or deleted, rejected
  WooCommerce API keys, users created or deleted, role, role definition and
  credential changes, plugin and theme changes, watched site and network
  options, order status changes and refunds.

Page and record content is not recorded, only identifiers. Records do contain
personal data and whatever the URL carries: user logins, IP addresses, user
agents, query strings such as search terms, and old and new values of watched
options such as `admin_email`. Known credential parameters are redacted, and
the query string is otherwise kept so a record still joins to its log line.

What a request read comes from the access log: join a record to its log line on
`ip`, `method` and `uri`, with the log timestamp within a few seconds after
`request_time` (nginx logs when the response finishes). REST sub-requests carry
their response `status`, so a denied call can be told from a successful one.

Failed logins keep the username only if the account exists; anything else is
stored as `username_sha256`, since people regularly type their password into
the username field.

## Cost on the site

Each recorded request makes one upload after the response has been sent, so
visitors don't wait, but the PHP worker stays busy for the upload (typically
100–300 ms). After a failed upload, uploads pause for five minutes and events
queue for the hourly retry, so an outage can't tie up workers. Failed logins,
rejected application passwords and rejected API keys always go through that
queue, so they reach the bucket within about an hour.

Page views by signed-in customers, WordPress Heartbeat, and Store API cart
calls are not recorded. Other admin-ajax and REST calls from signed-in
customers are.

## Storage

`gs://genero-audit-logs` (project `genero-audit-logs`, `europe-north1`):

```
<site>/logs/<rotation-date>/access.log-<date>-<epoch>.<sha256>.log.gz
<site>/events/<date>/<hour>/<time>-<random>.ndjson
```

Each site has its own service account with Storage Object Creator on its own
managed folder: it can upload but not list, read, overwrite or delete. Objects
are retained for 6 months (the policy gets locked after the pilot) and deleted
after 2 years. Reads and deletes of the bucket are themselves logged to the
`storage-audit-trail` log bucket.

## Installation

Requires the Genero Satis repo in the consuming project's `composer.json`:

```json
{
  "repositories": [
    { "type": "composer", "url": "https://generoi.github.io/packagist" }
  ]
}
```

```bash
composer require generoi/wp-audit-log
```

Create the site's credentials (as an owner of the `genero-audit-logs` project)
and add the printed lines to the **live** site's `.env`:

```bash
bin/onboard-site.sh <site> <host>[,<host>...]
```

| Variable | |
|---|---|
| `AUDIT_LOG_SITE` | Folder name in the bucket |
| `AUDIT_LOG_HOSTS` | Every live hostname, comma-separated, including `www.` and multisite domains |
| `AUDIT_LOG_ACCESS_ID`, `AUDIT_LOG_SECRET` | The site's HMAC key |
| `AUDIT_LOG_CHAT_WEBHOOK` | Optional: Google Chat webhook for upload failures |
| `AUDIT_LOG_DIR` | Optional: overrides the detected Kinsta `logs/` directory |
| `AUDIT_LOG_BUCKET` | Optional: defaults to `genero-audit-logs` |

The plugin does nothing unless `WP_ENV` is `production` and this server's own
access log shows traffic for a host in `AUDIT_LOG_HOSTS`. A copied `.env`, on a
Kinsta staging restore or in DDEV, therefore stays inactive, because those
environments have other hosts in their logs, or no logs at all. On live,
requests through any hostname are recorded, including the Kinsta temporary
domain, and each record shows its `host`.

## Development

Tests run against a real WordPress in [wp-env](https://www.npmjs.com/package/@wordpress/env):

```bash
composer install
npx @wordpress/env start
composer test:wp-env
composer lint
```
