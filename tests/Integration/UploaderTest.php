<?php

namespace GeneroWP\AuditLog\Tests\Integration;

use GeneroWP\AuditLog\Tests\TestCase;
use GeneroWP\AuditLog\Uploader;

class UploaderTest extends TestCase
{
    public function test_maps_responses(): void
    {
        $uploader = new Uploader(self::config());

        $this->respond(200);
        $this->assertSame(Uploader::CREATED, $uploader->put('example/a', 'x', 'text/plain'));

        $this->respond(412);
        $this->assertSame(Uploader::EXISTS, $uploader->put('example/b', 'x', 'text/plain'));
    }

    public function test_sends_a_signed_put(): void
    {
        (new Uploader(self::config()))->put('example/a b', 'x', 'text/plain');

        [$upload] = $this->uploads();
        $this->assertSame('PUT', $upload['method']);
        $this->assertSame('https://storage.googleapis.com/genero-audit-logs/example/a%20b', $upload['url']);
        $this->assertSame('0', $upload['headers']['x-goog-if-generation-match']);
        $this->assertStringStartsWith('GOOG4-HMAC-SHA256 Credential=GOOG1EXAMPLE/', $upload['headers']['authorization']);
    }

    public function test_existing_object_does_not_trip_the_breaker(): void
    {
        $uploader = new Uploader(self::config());

        $this->respond(412, 200);
        $uploader->put('example/a', 'x', 'text/plain');

        $this->assertSame(Uploader::CREATED, $uploader->put('example/b', 'x', 'text/plain'));
        $this->assertCount(2, $this->uploads());
    }

    /**
     * @testWith [0]
     *           [403]
     *           [503]
     */
    public function test_failure_opens_the_breaker_and_skips_further_requests(int $status): void
    {
        $uploader = new Uploader(self::config());

        $this->respond($status);
        $this->assertSame(Uploader::FAILED, $uploader->put('example/a', 'x', 'text/plain'));
        $this->assertSame(Uploader::FAILED, $uploader->put('example/b', 'x', 'text/plain'));

        $this->assertCount(1, $this->uploads());
    }
}
