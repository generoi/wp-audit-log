<?php

// Unit tests run without WordPress: tests/stubs.php supplies in-memory
// versions of the functions the plugin calls.
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/stubs.php';

wp_stub_reset();
ini_set('error_log', '/dev/null');
