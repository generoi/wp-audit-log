<?php

namespace GeneroWP\AuditLog;

class Plugin
{
    private static ?self $instance = null;

    public static function getInstance(): self
    {
        return self::$instance ??= new self;
    }

    private function __construct()
    {
        $config = Config::fromEnvironment();
        if (! $config->isActive()) {
            return;
        }

        $uploader = new Uploader($config);
        $shipper = new LogShipper($config, $uploader);

        // Registered immediately rather than on init: authentication hooks
        // like determine_current_user can fire before init.
        (new Recorder($config, $uploader))->register();

        add_action(LogShipper::HOOK, [$shipper, 'run']);
        // admin_init also fires for anonymous admin-ajax calls; only check on
        // real admin page loads.
        add_action('admin_init', function () use ($shipper): void {
            if (! wp_doing_ajax() && current_user_can('manage_options')) {
                $shipper->checkHealth();
            }
        });

        // Cron is per blog on multisite; one network-wide schedule is enough.
        add_action('init', function (): void {
            if (is_main_site() && ! wp_next_scheduled(LogShipper::HOOK)) {
                wp_schedule_event(time(), 'hourly', LogShipper::HOOK);
            }
        });
    }
}
