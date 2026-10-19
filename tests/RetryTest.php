<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\Retry;
use GeneroWP\AuditLog\Uploader;

class RetryTest extends StubbedTestCase
{
    public function test_queue_is_not_autoloaded_on_single_site(): void
    {
        Retry::push('example/a', 'x');

        $this->assertFalse($GLOBALS['wp_stub']['autoload']['wp_audit_log_retry']);
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

        $this->assertTrue(Retry::flush(new Uploader($this->config())));
        $this->assertSame(0, Retry::count());
        $this->assertCount(2, $this->uploads());
    }

    public function test_flush_stops_at_first_failure_and_keeps_the_rest(): void
    {
        Retry::push('example/a', 'a');
        Retry::push('example/b', 'b');
        Retry::push('example/c', 'c');

        $this->respond(200, 503);
        $this->assertFalse(Retry::flush(new Uploader($this->config())));

        $this->assertSame(['example/b', 'example/c'], array_keys(get_option('wp_audit_log_retry')));
    }
}
