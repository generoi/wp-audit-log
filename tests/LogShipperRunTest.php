<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\LogShipper;
use GeneroWP\AuditLog\Uploader;

class LogShipperRunTest extends StubbedTestCase
{
    private function run_shipper(array $overrides = []): void
    {
        $config = $this->config($overrides);
        (new LogShipper($config, new Uploader($config)))->run();
    }

    public function test_ships_each_rotated_file_once_and_never_the_live_one(): void
    {
        $this->log('access.log', self::line('www.example.fi', '/live'));
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi', '/a'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi', '/b'));

        $this->run_shipper();
        $this->run_shipper();

        $urls = array_column($this->uploads(), 'url');
        $this->assertCount(2, $urls);
        $this->assertStringContainsString('/example/logs/2026-10-18/access.log-2026-10-18-1.', $urls[0]);
        $this->assertStringContainsString('/example/logs/2026-10-19/access.log-2026-10-19-2.', $urls[1]);
        $this->assertEqualsWithDelta(time(), get_option('wp_audit_log_last_success'), 2);
    }

    public function test_file_without_our_hosts_is_skipped_and_does_not_block_others(): void
    {
        $this->log('access.log-2026-10-18-1', self::line('stg-example-staging.kinsta.cloud'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->run_shipper();

        $this->assertCount(1, $this->uploads());
        $this->assertArrayNotHasKey('access.log-2026-10-18-1', get_option('wp_audit_log_shipped'));
        $this->assertFalse(get_option('wp_audit_log_last_success'));
    }

    public function test_upload_failure_stops_the_run_and_retries_next_time(): void
    {
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->respond(503);
        $this->run_shipper();
        $this->assertCount(1, $this->uploads());
        $this->assertSame([], get_option('wp_audit_log_shipped'));

        unset($GLOBALS['wp_stub']['transients']['wp_audit_log_unreachable']);
        $this->run_shipper();
        $this->assertCount(3, $this->uploads());
        $this->assertCount(2, get_option('wp_audit_log_shipped'));
    }

    public function test_already_uploaded_file_counts_as_shipped(): void
    {
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));

        $this->respond(412);
        $this->run_shipper();

        $this->assertArrayHasKey('access.log-2026-10-18-1', get_option('wp_audit_log_shipped'));
    }

    public function test_forgets_files_kinsta_has_deleted(): void
    {
        update_site_option('wp_audit_log_shipped', ['access.log-2026-10-01-1' => 1]);
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));

        $this->run_shipper();

        $this->assertSame(['access.log-2026-10-18-1'], array_keys(get_option('wp_audit_log_shipped')));
    }

    public function test_reports_stale_uploads_to_chat_once_per_window(): void
    {
        update_site_option('wp_audit_log_first_seen', time() - 40 * HOUR_IN_SECONDS);
        $config = $this->config(['chatWebhook' => 'https://chat.example/hook']);
        $shipper = new LogShipper($config, new Uploader($config));

        $shipper->checkHealth();
        $shipper->checkHealth();

        $posts = array_values(array_filter($GLOBALS['wp_stub']['requests'], fn ($r) => $r['url'] === 'https://chat.example/hook'));
        $this->assertCount(1, $posts);
        $this->assertStringContainsString('no successful upload in 40 h', $posts[0]['body']);
    }

    public function test_serves_hosts_reads_this_servers_log(): void
    {
        $this->log('access.log', self::line('www.example.fi'));
        $this->assertTrue(LogShipper::servesHosts("{$this->root}/logs", $this->config()));

        $this->log('access.log', self::line('stg-example-staging.kinsta.cloud'));
        $this->assertFalse(LogShipper::servesHosts("{$this->root}/logs", $this->config()));
    }

    public function test_serves_hosts_falls_back_to_the_newest_rotated_file_after_midnight(): void
    {
        $this->log('access.log', '');
        $this->log('access.log-2026-10-18-1', self::line('stg-example-staging.kinsta.cloud'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->assertTrue(LogShipper::servesHosts("{$this->root}/logs", $this->config()));
    }
}
