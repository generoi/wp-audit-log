<?php

namespace GeneroWP\AuditLog\Tests;

use GeneroWP\AuditLog\Recorder;
use GeneroWP\AuditLog\Uploader;
use WP_REST_Request;
use WP_User;

class RecorderTest extends StubbedTestCase
{
    private Recorder $recorder;

    protected function setUp(): void
    {
        parent::setUp();

        $config = $this->config();
        $this->recorder = new Recorder($config, new Uploader($config));

        $GLOBALS['wp_stub']['users'][7] = new WP_User(7, 'editor', 'editor@example.fi', 'hash');
        $_SERVER += [
            'HTTP_HOST' => 'www.example.fi',
            'REMOTE_ADDR' => '1.2.3.4',
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'SCRIPT_NAME' => '/index.php',
        ];
    }

    private function signIn(): void
    {
        $GLOBALS['wp_stub']['current_user'] = 7;
        $cookie = 'editor|1792500000|tok3n|hmac';
        $_COOKIE[LOGGED_IN_COOKIE] = $cookie;
        $GLOBALS['wp_stub']['valid_cookie'] = $cookie;
    }

    public static function setUpBeforeClass(): void
    {
        if (! defined('LOGGED_IN_COOKIE')) {
            define('LOGGED_IN_COOKIE', 'wordpress_logged_in_test');
        }
    }

    public function test_login_records_the_new_sessions_hash(): void
    {
        $this->recorder->onLoggedInCookie('', 0, 0, 7, 'logged_in', 'tok3n');
        $this->recorder->onLogin('editor', get_userdata(7));
        $this->recorder->flush();

        [$record] = $this->uploadedRecords();
        $this->assertSame('login', $record['event']);
        $this->assertSame(hash('sha256', 'tok3n'), $record['data']['session']);
        $this->assertSame('http', $record['context']);
        $this->assertSame('1.2.3.4', $record['ip']);
    }

    public function test_later_cookie_requests_carry_the_same_session_hash(): void
    {
        $this->signIn();
        $GLOBALS['wp_stub']['admin'] = true;
        $_SERVER['REQUEST_URI'] = '/wp/wp-admin/admin.php?page=wc-orders&action=edit&id=55';

        $this->recorder->flush();

        [$record] = $this->uploadedRecords();
        $this->assertSame('request', $record['event']);
        $this->assertSame('editor', $record['user_login']);
        $this->assertSame(['method' => 'cookie', 'session' => hash('sha256', 'tok3n')], $record['credential']);
    }

    public function test_cookie_that_does_not_validate_is_not_credited(): void
    {
        $this->signIn();
        $GLOBALS['wp_stub']['valid_cookie'] = null;
        $GLOBALS['wp_stub']['admin'] = true;

        $this->recorder->flush();

        $this->assertSame(['method' => 'other'], $this->uploadedRecords()[0]['credential']);
    }

    public function test_failed_login_keeps_real_usernames_and_hashes_anything_else(): void
    {
        $this->recorder->onLoginFailed('editor');
        $this->recorder->onLoginFailed('hunter2-typed-as-username');
        $this->recorder->flush();

        [$real, $unknown] = $this->uploadedRecords();
        $this->assertSame(['username' => 'editor'], $real['data']);
        $this->assertSame(['username_sha256' => hash('sha256', 'hunter2-typed-as-username')], $unknown['data']);
    }

    public function test_application_password_request_records_its_uuid_and_rest_calls(): void
    {
        $GLOBALS['wp_stub']['current_user'] = 7;
        $this->recorder->onApplicationPassword(get_userdata(7), ['uuid' => 'abc-123']);
        $this->recorder->onRestCall(null, null, new WP_REST_Request('GET', '/wc/v3/orders/55', ['id' => 55]));
        $this->recorder->flush();

        [$record] = $this->uploadedRecords();
        $this->assertSame(['method' => 'application_password', 'uuid' => 'abc-123'], $record['credential']);
        $this->assertSame([['method' => 'GET', 'route' => '/wc/v3/orders/55', 'id' => '55']], $record['data']['rest']);
    }

    public function test_signed_in_frontend_browsing_is_not_recorded(): void
    {
        $this->signIn();
        $_SERVER['REQUEST_URI'] = '/product/hammer/';

        $this->recorder->flush();

        $this->assertSame([], $this->uploads());
    }

    public function test_background_loopbacks_are_not_recorded(): void
    {
        $this->signIn();
        $GLOBALS['wp_stub']['admin'] = true;
        $_SERVER['SCRIPT_NAME'] = '/wp/wp-admin/admin-ajax.php';

        foreach (['as_async_request_queue_runner', 'wp_1_wc_privacy_cleanup'] as $action) {
            $_REQUEST['action'] = $action;
            $this->recorder->flush();
        }
        $this->assertSame([], $this->uploads());

        $_REQUEST['action'] = $_POST['action'] = 'heartbeat';
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->recorder->flush();
        $this->assertSame(['action' => 'heartbeat'], $this->uploadedRecords()[0]['data']['params']);
    }

    public function test_requests_for_other_hosts_are_dropped(): void
    {
        $_SERVER['HTTP_HOST'] = 'stg-example-staging.kinsta.cloud';
        $this->recorder->onLoginFailed('editor');

        $this->recorder->flush();

        $this->assertSame([], $this->uploads());
    }

    public function test_cron_on_a_server_without_live_traffic_is_dropped(): void
    {
        // A staging restore: WP_HOME, and so HTTP_HOST, still says live.
        $GLOBALS['wp_stub']['cron'] = true;
        $this->log('access.log', self::line('stg-example-staging.kinsta.cloud'));
        $this->recorder->onOrderStatusChanged(55, 'pending', 'cancelled');

        $this->recorder->flush();

        $this->assertSame([], $this->uploads());
    }

    public function test_cron_on_live_is_recorded(): void
    {
        $GLOBALS['wp_stub']['cron'] = true;
        $this->log('access.log', self::line('www.example.fi'));
        $this->recorder->onOrderStatusChanged(55, 'pending', 'cancelled');

        $this->recorder->flush();

        [$record] = $this->uploadedRecords();
        $this->assertSame('cron', $record['context']);
        $this->assertSame(['order_id' => 55, 'from' => 'pending', 'to' => 'cancelled'], $record['data']);
    }

    public function test_query_string_credentials_are_redacted_from_the_uri(): void
    {
        $GLOBALS['wp_stub']['current_user'] = 7;
        $_SERVER['REQUEST_URI'] = '/wp-json/wc/v3/orders?consumer_key=ck_1&consumer_secret=cs_2';

        $this->recorder->flush();

        $this->assertSame('/wp-json/wc/v3/orders?consumer_key=REDACTED&consumer_secret=REDACTED', $this->uploadedRecords()[0]['uri']);
    }

    public function test_failed_upload_goes_to_the_retry_queue(): void
    {
        $this->recorder->onLoginFailed('editor');
        $this->respond(503);

        $this->recorder->flush();

        $this->assertCount(1, get_option('wp_audit_log_retry'));
    }

    public function test_hooks_called_with_missing_arguments_do_not_fatal(): void
    {
        $this->recorder->onLogin();
        $this->recorder->onProfileUpdated(7);
        $this->recorder->onUpgrade();
        $this->recorder->onRestCall('response');

        $this->recorder->flush();

        $this->assertSame('login', $this->uploadedRecords()[0]['event']);
    }
}
