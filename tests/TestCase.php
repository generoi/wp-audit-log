<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\Config;
use WP_UnitTestCase;

/**
 * Captures outgoing HTTP instead of sending it, and gives each test its own
 * Kinsta-style logs directory.
 */
abstract class TestCase extends WP_UnitTestCase
{
    protected string $root;

    /** @var array<int, array<string, mixed>> */
    protected array $requests = [];

    /** @var int[] Queued response codes; 0 means a network error. */
    protected array $responses = [];

    public function set_up(): void
    {
        parent::set_up();

        $this->root = sys_get_temp_dir().'/wp-audit-log-'.bin2hex(random_bytes(4));
        mkdir("{$this->root}/logs", 0777, true);

        add_filter('pre_http_request', function ($pre, array $args, string $url) {
            $this->requests[] = ['url' => $url] + $args;
            $status = array_shift($this->responses) ?? 200;

            return $status === 0
                ? new \WP_Error('http_request_failed', 'test')
                : ['headers' => [], 'body' => '', 'response' => ['code' => $status, 'message' => ''], 'cookies' => [], 'filename' => null];
        }, 10, 3);
    }

    public function tear_down(): void
    {
        exec('rm -rf '.escapeshellarg($this->root));
        parent::tear_down();
    }

    public static function config(array $overrides = []): Config
    {
        return new Config(...$overrides + [
            'environment' => 'production',
            'site' => 'example',
            'bucket' => 'genero-audit-logs',
            'accessId' => 'GOOG1EXAMPLE',
            'secret' => 'secret',
            'hosts' => ['example.fi', 'www.example.fi'],
            'logDir' => null,
            'chatWebhook' => null,
        ]);
    }

    protected function siteConfig(array $overrides = []): Config
    {
        return self::config($overrides + ['logDir' => "{$this->root}/logs"]);
    }

    protected function log(string $name, string $contents): void
    {
        file_put_contents("{$this->root}/logs/{$name}", $contents);
    }

    protected static function line(string $host, string $uri = '/'): string
    {
        return "{$host} 1.2.3.4 [19/Oct/2026:12:45:47 +0000] GET \"{$uri}\" HTTP/2.0 200 \"-\" \"UA\"\n";
    }

    protected function respond(int ...$statuses): void
    {
        $this->responses = $statuses;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function uploads(): array
    {
        return array_values(array_filter(
            $this->requests,
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
}
