<?php

namespace GeneroWP\AuditLog;

/**
 * Masks credentials that clients put in query strings. WooCommerce API keys
 * in particular are often sent as ?consumer_key=…&consumer_secret=…, and the
 * logs are locked for six months, so the secrets must not reach the bucket.
 */
class Redactor
{
    private const PARAMS = [
        'access_token',
        'api_key',
        'consumer_key',
        'consumer_secret',
        'key',
        'oauth_signature',
        'pass',
        'password',
        'pwd',
        'secret',
        'token',
    ];

    public static function redact(string $text): string
    {
        $names = implode('|', array_map('preg_quote', self::PARAMS));

        return preg_replace(
            '/([?&;](?:'.$names.')=)[^&\s"]*/i',
            '$1REDACTED',
            $text,
        ) ?? $text;
    }
}
