<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\LogShipper;
use PHPUnit\Framework\TestCase;

class LogShipperTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/wp-audit-log-'.bin2hex(random_bytes(4));
        mkdir("{$this->root}/logs", 0777, true);
        mkdir("{$this->root}/public/releases/221/web/wp", 0777, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->root));
    }

    private function log(string $name, string $contents): string
    {
        file_put_contents("{$this->root}/logs/{$name}", $contents);

        return "{$this->root}/logs/{$name}";
    }

    public function test_finds_kinsta_log_dir_from_bedrock_abspath(): void
    {
        $this->log('access.log', '');

        $this->assertSame("{$this->root}/logs", LogShipper::findLogDir("{$this->root}/public/releases/221/web/wp/"));
    }

    public function test_returns_null_without_log_dir(): void
    {
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

    public function test_pack_redacts_compresses_and_counts_allowed_hosts(): void
    {
        $lines = 'www.example.fi 1.2.3.4 [19/Oct/2026:12:45:47 +0000] GET "/wp-json/wc/v3/orders?consumer_secret=cs_x" HTTP/2.0 200'."\n"
            .'example.kinsta.cloud 5.6.7.8 [19/Oct/2026:12:45:48 +0000] GET "/" HTTP/2.0 200'."\n";
        $path = $this->log('access.log-2026-10-19-1792368010', $lines);

        $packed = LogShipper::pack($path, ConfigTest::config());
        $plain = gzdecode($packed['body']);

        $this->assertSame(1, $packed['allowed_lines']);
        $this->assertStringContainsString('consumer_secret=REDACTED', $plain);
        $this->assertStringNotContainsString('cs_x', $plain);
        $this->assertSame(hash('sha256', $plain), $packed['sha256']);
    }

    public function test_pack_finds_no_allowed_lines_in_staging_log(): void
    {
        $path = $this->log('access.log-2026-10-19-1', 'stg-example-staging.kinsta.cloud 1.2.3.4 [..] GET "/" HTTP/2.0 200'."\n");

        $this->assertSame(0, LogShipper::pack($path, ConfigTest::config())['allowed_lines']);
    }

    public function test_pack_returns_null_for_unreadable_file(): void
    {
        $this->assertNull(LogShipper::pack("{$this->root}/logs/missing", ConfigTest::config()));
    }
}
