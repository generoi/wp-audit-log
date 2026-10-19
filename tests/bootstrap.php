<?php

require_once dirname(__DIR__).'/vendor/autoload.php';

require_once getenv('WP_PHPUNIT__DIR').'/includes/functions.php';

// The plugin itself stays inactive here (WP_ENV is not production); tests
// build its components with their own Config instead.
tests_add_filter('muplugins_loaded', function () {
    require dirname(__DIR__).'/wp-audit-log.php';
});

require getenv('WP_PHPUNIT__DIR').'/includes/bootstrap.php';

// The shipper reports problems through error_log(); keep test output readable.
ini_set('error_log', '/dev/null');
