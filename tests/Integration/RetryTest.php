<?php

namespace GeneroWP\AuditLog\Tests\Integration;

use GeneroWP\AuditLog\Retry;
use GeneroWP\AuditLog\Tests\TestCase;
use GeneroWP\AuditLog\Uploader;

class RetryTest extends TestCase
{
    public function test_queue_is_not_autoloaded(): void
    {
        global $wpdb;

        Retry::push("a\n");

        $autoload = $wpdb->get_var("SELECT autoload FROM {$wpdb->options} WHERE option_name LIKE 'wp\_audit\_log\_retry\_%'");
        $this->assertContains($autoload, ['no', 'off']);
    }

    public function test_flush_merges_batches_into_one_upload_and_empties_the_queue(): void
    {
        Retry::push("a\n");
        Retry::push("b\n");

        $this->assertTrue(Retry::flush(new Uploader(self::config())));

        $this->assertSame(0, Retry::count());
        $this->assertCount(1, $this->uploads());
        $this->assertSame("a\nb\n", $this->uploads()[0]['body']);
    }

    public function test_failed_flush_keeps_the_queue(): void
    {
        Retry::push("a\n");
        Retry::push("b\n");

        $this->respond(503);

        $this->assertFalse(Retry::flush(new Uploader(self::config())));
        $this->assertSame(2, Retry::count());
    }

    public function test_trim_drops_nothing_under_the_cap(): void
    {
        Retry::push("a\n");

        $this->assertSame(0, Retry::trim());
        $this->assertSame(1, Retry::count());
    }

    public function test_trim_drops_the_oldest_past_the_cap(): void
    {
        global $wpdb;

        Retry::push("oldest\n");
        $wpdb->query("INSERT INTO {$wpdb->options} (option_name, option_value, autoload)
            SELECT CONCAT('wp_audit_log_retry_', a.n, b.n, c.n, d.n), 'x', 'off'
            FROM (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) a,
            (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) b,
            (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) c,
            (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) d");

        $this->assertSame(1, Retry::trim());
        $this->assertSame(10000, Retry::count());
        $this->assertNull($wpdb->get_var("SELECT option_id FROM {$wpdb->options} WHERE option_value = 'oldest\n'"));
    }
}
