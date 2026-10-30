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
        'apikey',
        'auth',
        'client_secret',
        'code',
        'consumer_key',
        'consumer_secret',
        'id_token',
        'key',
        'oauth_signature',
        'otp',
        'pass',
        'password',
        'pwd',
        'refresh_token',
        'secret',
        'sig',
        'signature',
        'token',
        'x-amz-signature',
        'x-goog-signature',
    ];

    /**
     * Also matches URL-encoded parameters, at any depth, because URLs nest in
     * other URLs: wp-login.php?redirect_to=…%3Fkey%3Dwc_order_…
     */
    public static function redact(string $text): string
    {
        $names = implode('|', array_map(fn (string $name) => preg_quote($name, '/'), self::PARAMS));
        $encoded = fn (string $hex) => '%(?:25)*'.$hex;
        $separator = '[?&;]|'.$encoded('3f').'|'.$encoded('26').'|'.$encoded('3b');
        $brackets = '\[\w*\]|'.$encoded('5b').'\w*'.$encoded('5d');
        $equals = '=|'.$encoded('3d');

        return preg_replace(
            '/((?:'.$separator.')(?:'.$names.')(?:'.$brackets.')?(?:'.$equals.'))(?:(?!'.$encoded('26').')[^&\s"])*/i',
            '$1REDACTED',
            $text,
        ) ?? $text;
    }
}
