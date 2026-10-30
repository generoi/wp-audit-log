<?php

namespace GeneroWP\AuditLog\Tests\Unit;

use GeneroWP\AuditLog\LogShipper;
use GeneroWP\AuditLog\Tests\TestCase;

class LogFilesTest extends TestCase
{
    public function test_finds_kinsta_log_dir_from_bedrock_abspath(): void
    {
        mkdir("{$this->root}/public/releases/221/web/wp", 0777, true);
        $this->log('access.log', '');

        $this->assertSame("{$this->root}/logs", LogShipper::findLogDir("{$this->root}/public/releases/221/web/wp/"));
    }

    public function test_returns_null_without_log_dir(): void
    {
        mkdir("{$this->root}/public/releases/221/web/wp", 0777, true);

        $this->assertNull(LogShipper::findLogDir("{$this->root}/public/releases/221/web/wp/"));
    }

    public function test_lists_only_rotated_access_logs_in_order(): void
    {
        foreach (['access.log', 'access.log-2026-10-19-1792368010', 'access.log-2026-10-18-1792288611',
            'access.log-2026-10-18-1792281611', 'error.log-2026-10-19-1792368010', 'cache-purge.log'] as $file) {
            $this->log($file, '');
        }

        $this->assertSame([
            'access.log-2026-10-18-1792281611',
            'access.log-2026-10-18-1792288611',
            'access.log-2026-10-19-1792368010',
        ], LogShipper::rotatedFiles("{$this->root}/logs"));
    }

    public function test_pack_redacts_and_compresses(): void
    {
        $this->log('access.log-2026-10-19-1', self::line('www.example.fi', '/wp-json/wc/v3/orders?consumer_secret=cs_x')
            .self::line('example.kinsta.cloud'));

        $packed = LogShipper::pack("{$this->root}/logs/access.log-2026-10-19-1");
        $plain = gzdecode($packed['body']);

        $this->assertStringContainsString('consumer_secret=REDACTED', $plain);
        $this->assertStringNotContainsString('cs_x', $plain);
        $this->assertStringContainsString('example.kinsta.cloud', $plain);
        $this->assertSame(hash('sha256', $plain), $packed['sha256']);
    }

    public function test_pack_returns_null_for_unreadable_file(): void
    {
        $this->assertNull(LogShipper::pack("{$this->root}/logs/missing"));
    }

    public function test_pack_returns_null_when_the_compressed_body_is_too_large(): void
    {
        // Random, so it doesn't compress; deflate flushes output in blocks.
        $this->log('access.log-2026-10-19-1', bin2hex(random_bytes(200000))."\n");

        $this->assertNull(LogShipper::pack("{$this->root}/logs/access.log-2026-10-19-1", 1));
    }

    public function test_serves_hosts_reads_this_servers_log(): void
    {
        $this->log('access.log', self::line('www.example.fi'));
        $this->assertTrue(LogShipper::servesHosts("{$this->root}/logs", self::config()));

        $this->log('access.log', self::line('stg-example-staging.kinsta.cloud'));
        $this->assertFalse(LogShipper::servesHosts("{$this->root}/logs", self::config()));
    }

    public function test_serves_hosts_falls_back_to_the_newest_rotated_file_after_midnight(): void
    {
        $this->log('access.log', '');
        $this->log('access.log-2026-10-18-1', self::line('stg-example-staging.kinsta.cloud'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->assertTrue(LogShipper::servesHosts("{$this->root}/logs", self::config()));
    }

    public function test_serves_hosts_is_not_fooled_by_other_hosts_filling_the_live_tail(): void
    {
        $this->log('access.log', self::line('example.kinsta.cloud'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->assertTrue(LogShipper::servesHosts("{$this->root}/logs", self::config()));
    }
}
