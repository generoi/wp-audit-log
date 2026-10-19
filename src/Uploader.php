<?php

namespace GeneroWP\AuditLog;

/**
 * Uploads objects through the GCS XML API with an HMAC key (V4 signing).
 *
 * The service account only holds Storage Object Creator on this site's
 * managed folder, and every upload sends x-goog-if-generation-match: 0, so
 * an existing object is never replaced: GCS answers 412 instead.
 */
class Uploader
{
    public const CREATED = 'created';

    public const EXISTS = 'exists';

    public const FAILED = 'failed';

    private const HOST = 'storage.googleapis.com';

    private const REGION = 'auto';

    /**
     * Set after a failed upload. Every signed-in admin or REST request
     * uploads, so without this an outage would hold a PHP worker for the
     * full timeout on each of them; while it is set, uploads go straight to
     * the retry queue instead.
     */
    private const BREAKER = 'wp_audit_log_unreachable';

    private const BREAKER_SECONDS = 300;

    public function __construct(private Config $config) {}

    /**
     * @return self::CREATED|self::EXISTS|self::FAILED
     */
    public function put(string $object, string $body, string $contentType, int $timeout = 10): string
    {
        if (get_site_transient(self::BREAKER)) {
            return self::FAILED;
        }

        $result = $this->send($object, $body, $contentType, $timeout);
        if ($result === self::FAILED) {
            set_site_transient(self::BREAKER, 1, self::BREAKER_SECONDS);
        }

        return $result;
    }

    /**
     * @return self::CREATED|self::EXISTS|self::FAILED
     */
    private function send(string $object, string $body, string $contentType, int $timeout): string
    {
        $headers = self::signedHeaders(
            accessId: $this->config->accessId,
            secret: $this->config->secret,
            bucket: $this->config->bucket,
            object: $object,
            body: $body,
            contentType: $contentType,
            time: time(),
        );

        $response = wp_remote_request(self::url($this->config->bucket, $object), [
            'method' => 'PUT',
            'headers' => $headers,
            'body' => $body,
            'timeout' => $timeout,
        ]);

        $status = is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);

        return match (true) {
            $status >= 200 && $status < 300 => self::CREATED,
            $status === 412 => self::EXISTS,
            default => self::FAILED,
        };
    }

    public static function url(string $bucket, string $object): string
    {
        return 'https://'.self::HOST.self::path($bucket, $object);
    }

    /**
     * @return array<string, string>
     */
    public static function signedHeaders(
        string $accessId,
        string $secret,
        string $bucket,
        string $object,
        string $body,
        string $contentType,
        int $time,
    ): array {
        $datetime = gmdate('Ymd\THis\Z', $time);
        $date = substr($datetime, 0, 8);
        $scope = "{$date}/".self::REGION.'/storage/goog4_request';

        $headers = [
            'content-type' => $contentType,
            'host' => self::HOST,
            'x-goog-content-sha256' => hash('sha256', $body),
            'x-goog-date' => $datetime,
            'x-goog-if-generation-match' => '0',
        ];
        ksort($headers);

        $canonicalHeaders = '';
        foreach ($headers as $name => $value) {
            $canonicalHeaders .= "{$name}:{$value}\n";
        }
        $signedHeaderNames = implode(';', array_keys($headers));

        $canonicalRequest = implode("\n", [
            'PUT',
            self::path($bucket, $object),
            '',
            $canonicalHeaders,
            $signedHeaderNames,
            $headers['x-goog-content-sha256'],
        ]);

        $stringToSign = implode("\n", [
            'GOOG4-HMAC-SHA256',
            $datetime,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);

        $key = hash_hmac('sha256', $date, 'GOOG4'.$secret, true);
        $key = hash_hmac('sha256', self::REGION, $key, true);
        $key = hash_hmac('sha256', 'storage', $key, true);
        $key = hash_hmac('sha256', 'goog4_request', $key, true);
        $signature = hash_hmac('sha256', $stringToSign, $key);

        unset($headers['host']);
        $headers['authorization'] = "GOOG4-HMAC-SHA256 Credential={$accessId}/{$scope}, "
            ."SignedHeaders={$signedHeaderNames}, Signature={$signature}";

        return $headers;
    }

    private static function path(string $bucket, string $object): string
    {
        return '/'.rawurlencode($bucket).'/'.implode('/', array_map('rawurlencode', explode('/', $object)));
    }
}
