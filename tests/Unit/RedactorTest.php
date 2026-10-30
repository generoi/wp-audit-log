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

    public function test_masks_encoded_parameters_in_nested_urls(): void
    {
        $this->assertSame(
            '/wp-login.php?redirect_to=https%3A%2F%2Fx.fi%2Forder-received%2F1%2F%3Fkey%3DREDACTED',
            Redactor::redact('/wp-login.php?redirect_to=https%3A%2F%2Fx.fi%2Forder-received%2F1%2F%3Fkey%3Dwc_order_XyZ'),
        );
        $this->assertSame(
            '/x?next=%2Fy%26consumer_secret%3DREDACTED%26page%3D2',
            Redactor::redact('/x?next=%2Fy%26consumer_secret%3Dcs_x%26page%3D2'),
        );
        $this->assertSame('/x?next=%253Ftoken%253DREDACTED', Redactor::redact('/x?next=%253Ftoken%253Dabc'));
    }

    public function test_masks_array_parameters(): void
    {
        $this->assertSame('/x?token[]=REDACTED&a=1', Redactor::redact('/x?token[]=abc&a=1'));
        $this->assertSame('/x?token%5B0%5D=REDACTED', Redactor::redact('/x?token%5B0%5D=abc'));
    }

    public function test_masks_oauth_and_signed_url_parameters(): void
    {
        foreach (['client_secret', 'refresh_token', 'id_token', 'code', 'auth', 'X-Amz-Signature', 'X-Goog-Signature'] as $name) {
            $this->assertSame("/cb?{$name}=REDACTED", Redactor::redact("/cb?{$name}=abc"));
        }
    }

    public function test_keeps_encoded_parameters_with_other_names(): void
    {
        $uri = '/?redirect_to=%2Fshop%3Fmonkey%3D1%26page%3D2';

        $this->assertSame($uri, Redactor::redact($uri));
    }

    public function test_redacts_inside_an_access_log_line(): void
    {
        $line = 'www.example.fi 1.2.3.4 [19/Oct/2026:12:45:47 +0000] GET "/wp-login.php?pwd=hunter2" HTTP/2.0 200 "-" "UA"';

        $this->assertStringContainsString('"/wp-login.php?pwd=REDACTED"', Redactor::redact($line));
    }
}
