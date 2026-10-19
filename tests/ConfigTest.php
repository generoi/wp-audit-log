<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\Config;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
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

    public function test_active_only_in_production_with_credentials_and_hosts(): void
    {
        $this->assertTrue(self::config()->isActive());
        $this->assertFalse(self::config(['environment' => 'staging'])->isActive());
        $this->assertFalse(self::config(['environment' => 'development'])->isActive());
        $this->assertFalse(self::config(['secret' => ''])->isActive());
        $this->assertFalse(self::config(['hosts' => []])->isActive());
    }

    public function test_host_check_is_case_insensitive_and_exact(): void
    {
        $config = self::config();

        $this->assertTrue($config->allowsHost('WWW.Example.fi'));
        $this->assertFalse($config->allowsHost('stg-example-staging.kinsta.cloud'));
        $this->assertFalse($config->allowsHost('example.ddev.site'));
        $this->assertFalse($config->allowsHost('evil-example.fi'));
    }

    public function test_parses_comma_separated_hosts(): void
    {
        $this->assertSame(['example.fi', 'www.example.fi'], Config::parseHosts(' Example.fi, www.example.fi ,'));
        $this->assertSame([], Config::parseHosts(''));
    }
}
