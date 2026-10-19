<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\Config;
use PHPUnit\Framework\TestCase;

abstract class StubbedTestCase extends TestCase
{
    protected string $root;

    protected function setUp(): void
    {
        wp_stub_reset();
        $_SERVER = ['REQUEST_TIME' => 1792413947];
        $_GET = $_POST = $_REQUEST = $_COOKIE = [];

        $this->root = sys_get_temp_dir().'/wp-audit-log-'.bin2hex(random_bytes(4));
        mkdir("{$this->root}/logs", 0777, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->root));
    }

    protected function config(array $overrides = []): Config
    {
        return ConfigTest::config($overrides + ['logDir' => "{$this->root}/logs"]);
    }

    protected function log(string $name, string $contents): void
    {
        file_put_contents("{$this->root}/logs/{$name}", $contents);
    }

    protected static function line(string $host, string $uri = '/'): string
    {
        return "{$host} 1.2.3.4 [19/Oct/2026:12:45:47 +0000] GET \"{$uri}\" HTTP/2.0 200 \"-\" \"UA\"\n";
    }

    /**
     * @return array<int, array{url: string, body: string}>
     */
    protected function uploads(): array
    {
        return array_values(array_filter(
            $GLOBALS['wp_stub']['requests'],
            fn (array $request) => str_starts_with($request['url'], 'https://storage.googleapis.com/'),
        ));
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function uploadedRecords(): array
    {
        $records = [];
        foreach ($this->uploads() as $upload) {
            foreach (array_filter(explode("\n", $upload['body'])) as $line) {
                $records[] = json_decode($line, true);
            }
        }

        return $records;
    }

    protected function respond(int ...$statuses): void
    {
        $GLOBALS['wp_stub']['responses'] = $statuses;
    }
}
