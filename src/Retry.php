<?php

namespace GeneroWP\AuditLog;

/**
 * Event uploads that failed during a request, retried by the hourly cron.
 * Capped so a long outage can't grow the option without bound; whatever is
 * dropped is still covered by the access log, just without identity.
 *
 * Concurrent requests can race on the read-modify-write and lose a batch;
 * that is accepted for the same reason.
 */
class Retry
{
    private const OPTION = 'wp_audit_log_retry';

    private const MAX = 500;

    public static function push(string $object, string $body): void
    {
        $queue = self::load();
        $queue[$object] = $body;
        self::save(array_slice($queue, -self::MAX, null, true));
    }

    public static function flush(Uploader $uploader): bool
    {
        $queue = self::load();
        if (! $queue) {
            return true;
        }

        foreach ($queue as $object => $body) {
            if ($uploader->put($object, $body, 'application/x-ndjson') === Uploader::FAILED) {
                self::save($queue);

                return false;
            }
            unset($queue[$object]);
        }

        self::save($queue);

        return true;
    }

    public static function count(): int
    {
        return count(self::load());
    }

    /**
     * @return array<string, string>
     */
    private static function load(): array
    {
        $queue = is_multisite() ? get_site_option(self::OPTION, []) : get_option(self::OPTION, []);

        return is_array($queue) ? $queue : [];
    }

    /**
     * Never autoloaded: the queue can hold hundreds of batches, and on a
     * single site update_site_option() would load them on every request.
     * (Network options are not autoloaded to begin with.)
     *
     * @param  array<string, string>  $queue
     */
    private static function save(array $queue): void
    {
        if (is_multisite()) {
            update_site_option(self::OPTION, $queue);
        } else {
            update_option(self::OPTION, $queue, false);
        }
    }
}
