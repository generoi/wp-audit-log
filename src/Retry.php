<?php

namespace GeneroWP\AuditLog;

/**
 * Event batches waiting for the hourly cron: uploads that failed during a
 * request, and failed logins, which are queued so that a credential-stuffing
 * run can't hold a PHP worker and make an upload per attempt.
 *
 * Each batch is its own row, so concurrent requests can't overwrite each
 * other. Rows go straight into the main site's options table because the
 * queue is network-wide, and because these names are never read as options.
 */
class Retry
{
    private const PREFIX = 'wp_audit_log_retry_';

    private const MAX = 10000;

    private const PER_UPLOAD = 1000;

    public static function push(string $body): void
    {
        global $wpdb;

        $wpdb->insert(self::table(), [
            'option_name' => self::PREFIX.bin2hex(random_bytes(8)),
            'option_value' => $body,
            'autoload' => 'off',
        ]);
    }

    /**
     * Uploads queued batches merged into one object per PER_UPLOAD rows. Each
     * record has its own timestamps, so its object's date only says when it
     * was uploaded.
     */
    public static function flush(Uploader $uploader): bool
    {
        global $wpdb;

        $table = self::table();

        while ($rows = $wpdb->get_results($wpdb->prepare(
            "SELECT option_id, option_value FROM {$table} WHERE option_name LIKE %s ORDER BY option_id LIMIT %d",
            self::like(),
            self::PER_UPLOAD,
        ))) {
            $body = implode('', array_column($rows, 'option_value'));
            if ($uploader->put($uploader->eventObject(), $body, 'application/x-ndjson') === Uploader::FAILED) {
                return false;
            }

            $ids = implode(',', array_map('intval', array_column($rows, 'option_id')));
            $wpdb->query("DELETE FROM {$table} WHERE option_id IN ({$ids})");
        }

        return true;
    }

    /**
     * Caps the queue so a long outage can't grow it without bound.
     *
     * @return int how many of the oldest batches were dropped
     */
    public static function trim(): int
    {
        global $wpdb;

        $excess = self::count() - self::MAX;
        if ($excess <= 0) {
            return 0;
        }

        $table = self::table();

        return (int) $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE option_name LIKE %s ORDER BY option_id LIMIT %d",
            self::like(),
            $excess,
        ));
    }

    public static function count(): int
    {
        global $wpdb;

        $table = self::table();

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE option_name LIKE %s",
            self::like(),
        ));
    }

    private static function table(): string
    {
        global $wpdb;

        return $wpdb->base_prefix.'options';
    }

    private static function like(): string
    {
        global $wpdb;

        return $wpdb->esc_like(self::PREFIX).'%';
    }
}
