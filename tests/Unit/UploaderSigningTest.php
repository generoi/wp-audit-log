<?php

namespace GeneroWP\AuditLog\Tests\Unit;

use GeneroWP\AuditLog\Tests\TestCase;
use GeneroWP\AuditLog\Uploader;

class UploaderSigningTest extends TestCase
{
    private function headers(array $overrides = []): array
    {
        return Uploader::signedHeaders(...$overrides + [
            'accessId' => 'GOOG1EXAMPLE',
            'secret' => 'secret',
            'bucket' => 'genero-audit-logs',
            'object' => 'example/events/2026-10-19/12/124547-abc.ndjson',
            'body' => "{}\n",
            'contentType' => 'application/x-ndjson',
            'time' => 1792413947,
        ]);
    }

    public function test_never_overwrites(): void
    {
        $this->assertSame('0', $this->headers()['x-goog-if-generation-match']);
    }

    public function test_authorization_header_shape(): void
    {
        $headers = $this->headers();

        $this->assertMatchesRegularExpression(
            '#^GOOG4-HMAC-SHA256 Credential=GOOG1EXAMPLE/20261019/auto/storage/goog4_request, '
            .'SignedHeaders=content-type;host;x-goog-content-sha256;x-goog-date;x-goog-if-generation-match, '
            .'Signature=[0-9a-f]{64}$#',
            $headers['authorization'],
        );
        $this->assertSame('20261019T124547Z', $headers['x-goog-date']);
        $this->assertSame(hash('sha256', "{}\n"), $headers['x-goog-content-sha256']);
        $this->assertArrayNotHasKey('host', $headers);
    }

    public function test_signature_covers_body_object_and_secret(): void
    {
        $signature = fn (array $o) => $this->headers($o)['authorization'];
        $base = $signature([]);

        $this->assertSame($base, $signature([]));
        $this->assertNotSame($base, $signature(['body' => "{} \n"]));
        $this->assertNotSame($base, $signature(['object' => 'other/events/x.ndjson']));
        $this->assertNotSame($base, $signature(['secret' => 'other']));
    }

    public function test_url_encodes_each_path_segment(): void
    {
        $this->assertSame(
            'https://storage.googleapis.com/genero-audit-logs/example/logs/2026-10-19/access.log-2026-10-19-1%20x.gz',
            Uploader::url('genero-audit-logs', 'example/logs/2026-10-19/access.log-2026-10-19-1 x.gz'),
        );
    }
}
