<?php

namespace GeneroWP\AuditLog;

/**
 * Uploads Kinsta's rotated access logs. Kinsta keeps only 3–4 days of
 * rotated files on disk, so an hourly run leaves plenty of room for retries.
 *
 * The live access.log is skipped until it rotates at midnight UTC, because
 * an object can't be replaced once uploaded.
 */
class LogShipper
{
    public const HOOK = 'wp_audit_log_ship';

    private const SHIPPED = 'wp_audit_log_shipped';

    private const LAST_SUCCESS = 'wp_audit_log_last_success';

    private const FIRST_SEEN = 'wp_audit_log_first_seen';

    /** Rotated files look like access.log-2026-10-19-1792368010. */
    private const ROTATED = '/^access\.log-(\d{4}-\d{2}-\d{2})-\d+$/';

    private const STALE_AFTER = 36 * 3600;

    public function __construct(private Config $config, private Uploader $uploader) {}

    public function run(): void
    {
        $dir = self::logDir($this->config);
        if (! $dir) {
            $this->notify('no-log-dir', 'cannot find the Kinsta logs directory; set AUDIT_LOG_DIR.');

            return;
        }

        $files = self::rotatedFiles($dir);
        // Forget files Kinsta has already deleted, so the option stays small.
        $shipped = array_intersect_key(get_site_option(self::SHIPPED, []), array_flip($files));
        $ok = true;

        foreach ($files as $file) {
            if (isset($shipped[$file])) {
                continue;
            }

            $result = $this->ship($dir, $file);
            if ($result === null) {
                $ok = false;

                continue;
            }
            if ($result === Uploader::FAILED) {
                // Storage is unreachable or refusing us; the rest would fail too.
                $ok = false;
                break;
            }
            $shipped[$file] = time();
        }

        update_site_option(self::SHIPPED, $shipped);

        $ok = Retry::flush($this->uploader) && $ok;
        if ($ok) {
            update_site_option(self::LAST_SUCCESS, time());
        }

        $this->checkHealth();
    }

    /**
     * Runs from the hourly cron and from admin requests, so a site whose cron
     * has stopped still raises the alarm the next time someone opens wp-admin.
     */
    public function checkHealth(): void
    {
        $firstSeen = (int) get_site_option(self::FIRST_SEEN, 0);
        if (! $firstSeen) {
            update_site_option(self::FIRST_SEEN, time());

            return;
        }

        $lastSuccess = (int) get_site_option(self::LAST_SUCCESS, 0) ?: $firstSeen;
        if (time() - $lastSuccess > self::STALE_AFTER) {
            $hours = (int) round((time() - $lastSuccess) / HOUR_IN_SECONDS);
            $this->notify('stale', "no successful upload in {$hours} h ({$this->pendingSummary()}).");
        }
    }

    /**
     * @return Uploader::CREATED|Uploader::EXISTS|Uploader::FAILED|null null when the file can't be shipped
     */
    private function ship(string $dir, string $file): ?string
    {
        preg_match(self::ROTATED, $file, $match);
        $packed = self::pack("{$dir}/{$file}", $this->config);

        if ($packed === null) {
            // Skip rather than stop, so one bad file can't hold back the rest
            // until Kinsta deletes them.
            $this->notify('unreadable', "cannot read {$file}.");

            return null;
        }

        if ($packed['allowed_lines'] === 0) {
            // Either AUDIT_LOG_HOSTS is wrong, or this file is not this site's
            // traffic at all. Never upload it under this site's name.
            $this->notify('foreign-hosts', "{$file} has no lines for AUDIT_LOG_HOSTS; not uploaded.");

            return null;
        }

        $object = sprintf('%s/logs/%s/%s.%s.log.gz', $this->config->site, $match[1], $file, $packed['sha256']);

        return $this->uploader->put($object, $packed['body'], 'application/gzip', 60);
    }

    /**
     * Redacts and gzips a log file line by line, so only the compressed
     * output is held in memory. The hash is of the redacted plain text and
     * becomes part of the object name, so a name can't be claimed in advance.
     *
     * @return array{body: string, sha256: string, allowed_lines: int}|null
     */
    public static function pack(string $path, Config $config): ?array
    {
        $handle = @fopen($path, 'rb');
        if (! $handle) {
            return null;
        }

        $deflate = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 6]);
        $hash = hash_init('sha256');
        $body = '';
        $allowed = 0;

        while (($line = fgets($handle)) !== false) {
            $line = Redactor::redact($line);
            if ($config->allowsHost(strtok($line, ' ') ?: '')) {
                $allowed++;
            }
            hash_update($hash, $line);
            $body .= deflate_add($deflate, $line, ZLIB_NO_FLUSH);
        }
        fclose($handle);

        $body .= deflate_add($deflate, '', ZLIB_FINISH);

        return ['body' => $body, 'sha256' => hash_final($hash), 'allowed_lines' => $allowed];
    }

    /**
     * @return string[]
     */
    public static function rotatedFiles(string $dir): array
    {
        $files = array_values(array_filter(
            scandir($dir) ?: [],
            fn (string $file) => (bool) preg_match(self::ROTATED, $file),
        ));
        sort($files);

        return $files;
    }

    public static function logDir(Config $config): ?string
    {
        return $config->logDir ?? self::findLogDir(ABSPATH);
    }

    /**
     * Kinsta keeps logs in /www/<site>_<id>/logs, a few levels above the
     * WordPress install: Bedrock's ABSPATH is …/public/current/web/wp/, or
     * the resolved release directory under …/public/releases/<n>/web/wp/.
     */
    public static function findLogDir(string $from): ?string
    {
        $dir = rtrim($from, '/');
        for ($i = 0; $i < 8 && $dir !== '' && $dir !== '/'; $i++) {
            if (is_file("{$dir}/logs/access.log")) {
                return "{$dir}/logs";
            }
            $dir = dirname($dir);
        }

        return null;
    }

    /**
     * Whether this server's own nginx log shows live traffic. Unlike .env and
     * the database, the logs directory belongs to the Kinsta environment and is
     * not copied by a backup restore, so a staging copy whose .env still
     * says WP_ENV=production and WP_HOME=<live domain> fails this check.
     */
    public static function servesHosts(string $dir, Config $config): bool
    {
        $candidates = array_reverse(self::rotatedFiles($dir));
        array_unshift($candidates, 'access.log');

        foreach ($candidates as $file) {
            $handle = @fopen("{$dir}/{$file}", 'rb');
            if (! $handle) {
                continue;
            }
            fseek($handle, -min(65536, (int) filesize("{$dir}/{$file}")), SEEK_END);
            $tail = (string) stream_get_contents($handle);
            fclose($handle);

            if ($tail === '') {
                continue;
            }
            foreach (explode("\n", $tail) as $line) {
                if ($config->allowsHost(strtok($line, ' ') ?: '')) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    private function pendingSummary(): string
    {
        return sprintf('%d event batches waiting to retry', Retry::count());
    }

    /**
     * Throttled per problem, so a site stuck in a failure state reports it
     * twice a day rather than on every admin page load.
     */
    private function notify(string $problem, string $message): void
    {
        $message = "wp-audit-log on {$this->config->site}: {$message}";
        error_log($message);

        $key = "wp_audit_log_notified_{$problem}";
        if (! $this->config->chatWebhook || get_site_transient($key)) {
            return;
        }
        set_site_transient($key, 1, 12 * HOUR_IN_SECONDS);

        wp_remote_post($this->config->chatWebhook, [
            'headers' => ['Content-Type' => 'application/json; charset=UTF-8'],
            'body' => wp_json_encode(['text' => $message]),
            'timeout' => 5,
        ]);
    }
}
