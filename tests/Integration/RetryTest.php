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

        Retry::push('example/a', 'x');

        $autoload = $wpdb->get_var("SELECT autoload FROM {$wpdb->options} WHERE option_name = 'wp_audit_log_retry'");
        $this->assertContains($autoload, ['no', 'off']);
    }

    public function test_queue_keeps_the_newest_500(): void
    {
        for ($i = 0; $i < 510; $i++) {
            Retry::push("example/{$i}", 'x');
        }

        $queue = get_option('wp_audit_log_retry');
        $this->assertCount(500, $queue);
        $this->assertArrayHasKey('example/509', $queue);
        $this->assertArrayNotHasKey('example/9', $queue);
    }

    public function test_flush_uploads_and_empties_the_queue(): void
    {
        Retry::push('example/a', 'a');
        Retry::push('example/b', 'b');

        $this->assertTrue(Retry::flush(new Uploader(self::config())));
        $this->assertSame(0, Retry::count());
        $this->assertCount(2, $this->uploads());
    }

    public function test_flush_stops_at_first_failure_and_keeps_the_rest(): void
    {
        Retry::push('example/a', 'a');
        Retry::push('example/b', 'b');
        Retry::push('example/c', 'c');

        $this->respond(200, 503);
        $this->assertFalse(Retry::flush(new Uploader(self::config())));

        $this->assertSame(['example/b', 'example/c'], array_keys(get_option('wp_audit_log_retry')));
    }
}
