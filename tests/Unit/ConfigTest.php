<?php

namespace GeneroWP\AuditLog\Tests\Unit;

use GeneroWP\AuditLog\Config;
use GeneroWP\AuditLog\Recorder;
use GeneroWP\AuditLog\Tests\TestCase;

class ConfigTest extends TestCase
{
    public function test_active_only_in_production_with_credentials_and_hosts(): void
    {
        $this->assertTrue(self::config()->isActive());
        $this->assertFalse(self::config(['environment' => 'staging'])->isActive());
        $this->assertFalse(self::config(['environment' => 'development'])->isActive());
        $this->assertFalse(self::config(['secret' => ''])->isActive());
        $this->assertFalse(self::config(['hosts' => []])->isActive());
    }

    public function test_plugin_is_inactive_in_this_environment(): void
    {
        $this->assertFalse(Config::fromEnvironment()->isActive());

        $recorders = array_filter(
            array_merge(...array_values($GLOBALS['wp_filter']['shutdown']->callbacks ?? [])),
            fn (array $hook) => is_array($hook['function']) && $hook['function'][0] instanceof Recorder,
        );
        $this->assertSame([], $recorders);
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
