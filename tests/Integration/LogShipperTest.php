<?php

namespace GeneroWP\AuditLog\Tests\Integration;

use GeneroWP\AuditLog\LogShipper;
use GeneroWP\AuditLog\Tests\TestCase;
use GeneroWP\AuditLog\Uploader;

class LogShipperTest extends TestCase
{
    private function ship(array $overrides = []): void
    {
        $config = $this->siteConfig($overrides);
        (new LogShipper($config, new Uploader($config)))->run();
    }

    public function test_ships_each_rotated_file_once_and_never_the_live_one(): void
    {
        $this->log('access.log', self::line('www.example.fi', '/live'));
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi', '/a'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi', '/b'));

        $this->ship();
        $this->ship();

        $uploads = $this->uploads();
        $this->assertCount(2, $uploads);
        $this->assertStringContainsString('/example/logs/2026-10-18/access.log-2026-10-18-1.', $uploads[0]['url']);
        $this->assertStringContainsString('/example/logs/2026-10-19/access.log-2026-10-19-2.', $uploads[1]['url']);
        $this->assertStringContainsString('"/b"', gzdecode($uploads[1]['body']));
        $this->assertEqualsWithDelta(time(), get_site_option('wp_audit_log_last_success'), 2);
    }

    public function test_live_uploads_files_with_only_other_hosts(): void
    {
        $this->log('access.log', self::line('www.example.fi'));
        $this->log('access.log-2026-10-18-1', self::line('example.kinsta.cloud'));

        $this->ship();

        $this->assertCount(1, $this->uploads());
        $this->assertEqualsWithDelta(time(), get_site_option('wp_audit_log_last_success'), 2);
    }

    public function test_staging_copy_uploads_nothing_and_does_not_alert(): void
    {
        update_site_option('wp_audit_log_first_seen', time() - 40 * HOUR_IN_SECONDS);
        $this->log('access.log', self::line('stg-example-staging.kinsta.cloud'));
        $this->log('access.log-2026-10-18-1', self::line('stg-example-staging.kinsta.cloud'));

        $this->ship(['chatWebhook' => 'https://chat.example/hook']);

        $this->assertSame([], $this->requests);
    }

    public function test_finding_nothing_to_ship_is_not_a_success(): void
    {
        $this->log('access.log', self::line('www.example.fi'));
        $this->log('access.log-renamed-by-kinsta.gz', 'x');

        $this->ship();

        $this->assertFalse(get_site_option('wp_audit_log_last_success'));
    }

    public function test_progress_survives_a_later_failure(): void
    {
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->respond(200, 503);
        $this->ship();

        $this->assertSame(['access.log-2026-10-18-1'], array_keys(get_site_option('wp_audit_log_shipped')));
    }

    public function test_upload_failure_stops_the_run_and_retries_next_time(): void
    {
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));
        $this->log('access.log-2026-10-19-2', self::line('www.example.fi'));

        $this->respond(503);
        $this->ship();
        $this->assertCount(1, $this->uploads());
        $this->assertSame([], get_site_option('wp_audit_log_shipped'));

        delete_site_transient('wp_audit_log_unreachable');
        $this->ship();
        $this->assertCount(3, $this->uploads());
        $this->assertCount(2, get_site_option('wp_audit_log_shipped'));
    }

    public function test_already_uploaded_file_counts_as_shipped(): void
    {
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));

        $this->respond(412);
        $this->ship();

        $this->assertArrayHasKey('access.log-2026-10-18-1', get_site_option('wp_audit_log_shipped'));
    }

    public function test_forgets_files_kinsta_has_deleted(): void
    {
        update_site_option('wp_audit_log_shipped', ['access.log-2026-10-01-1' => 1]);
        $this->log('access.log-2026-10-18-1', self::line('www.example.fi'));

        $this->ship();

        $this->assertSame(['access.log-2026-10-18-1'], array_keys(get_site_option('wp_audit_log_shipped')));
    }

    public function test_reports_stale_uploads_to_chat_once_per_window(): void
    {
        update_site_option('wp_audit_log_first_seen', time() - 40 * HOUR_IN_SECONDS);
        $config = $this->siteConfig(['chatWebhook' => 'https://chat.example/hook']);
        $shipper = new LogShipper($config, new Uploader($config));

        $shipper->checkHealth();
        $shipper->checkHealth();

        $posts = array_values(array_filter($this->requests, fn ($r) => $r['url'] === 'https://chat.example/hook'));
        $this->assertCount(1, $posts);
        $this->assertStringContainsString('no successful upload in 40 h', $posts[0]['body']);
    }
}
