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

    /** The compressed file is held in memory; a fatal here would repeat every hour. */
    private const MAX_BODY = 64 * 1024 * 1024;

    public function __construct(private Config $config, private Uploader $uploader) {}

    public function run(): void
    {
        $dir = self::logDir($this->config);
        if (! $dir) {
            $this->notify('no-log-dir', 'cannot find the Kinsta logs directory; set AUDIT_LOG_DIR.');

            return;
        }

        // A staging copy stays silent. A wrong AUDIT_LOG_HOSTS on live looks
        // the same from here, and is caught by the external check of the bucket.
        if (! self::servesHosts($dir, $this->config)) {
            return;
        }

        $files = self::rotatedFiles($dir);
        // Forget files Kinsta has already deleted, so the option stays small.
        $shipped = array_intersect_key(get_site_option(self::SHIPPED, []), array_flip($files));
        $uploaded = false;

        foreach ($files as $file) {
            if (isset($shipped[$file])) {
                continue;
            }

            $result = $this->ship($dir, $file);
            if ($result === null) {
                continue;
            }
            if ($result === Uploader::FAILED) {
                // Storage is unreachable or refusing us; the rest would fail too.
                break;
            }
            $uploaded = true;
            $shipped[$file] = time();
            // Saved per file, so a run that dies on a later file keeps its progress.
            update_site_option(self::SHIPPED, $shipped);
        }

        update_site_option(self::SHIPPED, $shipped);

        // Only a real upload counts: finding no files to ship must eventually
        // alert, in case Kinsta changes how it names or stores rotated logs.
        if ($uploaded) {
            update_site_option(self::LAST_SUCCESS, time());
        }

        Retry::flush($this->uploader);
        $dropped = Retry::trim();
        if ($dropped) {
            $this->notify('retry-dropped', "dropped the {$dropped} oldest queued event batches.");
        }

        $this->checkHealth();
    }

    /**
     * Reports uploads that keep failing while cron is running. A site that
     * stops running cron altogether is caught by the external daily check
     * of the bucket instead.
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
        $packed = self::pack("{$dir}/{$file}");

        if ($packed === null) {
            // Skip rather than stop, so one bad file can't hold back the rest
            // until Kinsta deletes them.
            $this->notify('unreadable', "cannot read {$file}, or it is too large.");

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
     * @return array{body: string, sha256: string}|null null when unreadable or over MAX_BODY
     */
    public static function pack(string $path, int $maxBody = self::MAX_BODY): ?array
    {
        $handle = @fopen($path, 'rb');
        if (! $handle) {
            return null;
        }

        $deflate = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 6]);
        $hash = hash_init('sha256');
        $body = '';

        while (($line = fgets($handle)) !== false) {
            $line = Redactor::redact($line);
            hash_update($hash, $line);
            $body .= deflate_add($deflate, $line, ZLIB_NO_FLUSH);

            if (strlen($body) > $maxBody) {
                fclose($handle);

                return null;
            }
        }
        fclose($handle);

        $body .= deflate_add($deflate, '', ZLIB_FINISH);

        return ['body' => $body, 'sha256' => hash_final($hash)];
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
     * says WP_ENV=production and WP_HOME=<live domain> fails this check, and
     * so does DDEV, which has no such directory.
     *
     * Every file on disk counts, so traffic on another hostname, such as the
     * Kinsta temporary domain, can't push the live hosts out of the tail.
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

            foreach (explode("\n", $tail) as $line) {
                if ($config->allowsHost(strtok($line, ' ') ?: '')) {
                    return true;
                }
            }
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
