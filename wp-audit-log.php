<?php

/*
Plugin Name:  Audit Log
Plugin URI:   https://genero.fi
Description:  Ships Kinsta access logs and per-request user identity to write-only Google Cloud Storage for incident forensics.
Version:      0.1.0
Author:       Genero
Author URI:   https://genero.fi/
License:      MIT License
License URI:  http://opensource.org/licenses/MIT
*/

use GeneroWP\AuditLog\Plugin;

if (! defined('ABSPATH')) {
    exit;
}

if (file_exists($composer = __DIR__.'/vendor/autoload.php')) {
    require_once $composer;
}

Plugin::getInstance();
