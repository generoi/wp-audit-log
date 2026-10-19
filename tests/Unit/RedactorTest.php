<?php

namespace GeneroWP\AuditLog\Tests\Unit;

use GeneroWP\AuditLog\Redactor;
use GeneroWP\AuditLog\Tests\TestCase;

class RedactorTest extends TestCase
{
    public function test_masks_woocommerce_keys_in_query_string(): void
    {
        $this->assertSame(
            '/wp-json/wc/v3/orders?consumer_key=REDACTED&consumer_secret=REDACTED&per_page=100',
            Redactor::redact('/wp-json/wc/v3/orders?consumer_key=ck_abc&consumer_secret=cs_def&per_page=100'),
        );
    }

    public function test_masks_order_key_but_keeps_order_id(): void
    {
        $this->assertSame(
            '/checkout/order-received/123/?key=REDACTED',
            Redactor::redact('/checkout/order-received/123/?key=wc_order_XyZ'),
        );
    }

    public function test_matches_whole_parameter_names_only(): void
    {
        $uri = '/?monkey=1&passage=2&tokens=3';

        $this->assertSame($uri, Redactor::redact($uri));
    }

    public function test_redacts_inside_an_access_log_line(): void
    {
        $line = 'www.example.fi 1.2.3.4 [19/Oct/2026:12:45:47 +0000] GET "/wp-login.php?pwd=hunter2" HTTP/2.0 200 "-" "UA"';

        $this->assertStringContainsString('"/wp-login.php?pwd=REDACTED"', Redactor::redact($line));
    }
}
