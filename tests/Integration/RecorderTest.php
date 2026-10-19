<?php

namespace GeneroWP\AuditLog\Tests\Integration;

use GeneroWP\AuditLog\Recorder;
use GeneroWP\AuditLog\Tests\TestCase;
use GeneroWP\AuditLog\Uploader;
use WP_Application_Passwords;
use WP_REST_Request;
use WP_Session_Tokens;

class RecorderTest extends TestCase
{
    private Recorder $recorder;

    private int $userId;

    private array $server;

    public function set_up(): void
    {
        parent::set_up();

        $this->server = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'www.example.fi';
        $_SERVER['REMOTE_ADDR'] = '1.2.3.4';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['SCRIPT_NAME'] = '/index.php';

        $this->userId = self::factory()->user->create([
            'user_login' => 'editor',
            'user_pass' => 'correct-horse',
            'role' => 'administrator',
        ]);

        $config = $this->siteConfig();
        $this->recorder = new Recorder($config, new Uploader($config));
        $this->recorder->register();

        // The cookies themselves can't be sent from the CLI; the actions that
        // carry the session token still fire before this filter is checked.
        add_filter('send_auth_cookies', '__return_false');
    }

    public function tear_down(): void
    {
        $_SERVER = $this->server;
        $_COOKIE = $_POST = $_REQUEST = [];
        unset($GLOBALS['current_screen']);
        parent::tear_down();
    }

    /**
     * A real session the way wp_signon() creates it, sent back as a cookie.
     */
    private function signIn(): string
    {
        $expiration = time() + DAY_IN_SECONDS;
        $token = WP_Session_Tokens::get_instance($this->userId)->create($expiration);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($this->userId, $expiration, 'logged_in', $token);
        wp_set_current_user($this->userId);

        return $token;
    }

    private function inAdmin(): void
    {
        require_once ABSPATH.'wp-admin/includes/class-wp-screen.php';
        require_once ABSPATH.'wp-admin/includes/screen.php';
        set_current_screen('dashboard');
    }

    private function allowApplicationPasswords(): void
    {
        add_filter('wp_is_application_passwords_available', '__return_true');
        add_filter('application_password_is_api_request', '__return_true');
    }

    public function test_login_records_the_new_sessions_hash(): void
    {
        $user = wp_signon(['user_login' => 'editor', 'user_password' => 'correct-horse']);
        $this->assertSame($this->userId, $user->ID);

        $this->recorder->flush();

        $login = $this->uploadedRecords()[0];
        $sessions = get_user_meta($this->userId, 'session_tokens', true);

        $this->assertSame('login', $login['event']);
        $this->assertArrayHasKey($login['data']['session'], $sessions, 'the hash is the verifier WordPress stores');
        $this->assertSame('http', $login['context']);
        $this->assertSame('1.2.3.4', $login['ip']);
    }

    public function test_later_cookie_requests_carry_the_same_session_hash(): void
    {
        $token = $this->signIn();
        $this->inAdmin();
        $_SERVER['REQUEST_URI'] = '/wp/wp-admin/admin.php?page=wc-orders&action=edit&id=55';

        $this->recorder->flush();

        [$record] = $this->uploadedRecords();
        $this->assertSame('request', $record['event']);
        $this->assertSame('editor', $record['user_login']);
        $this->assertSame(['method' => 'cookie', 'session' => hash('sha256', $token)], $record['credential']);
    }

    public function test_cookie_for_another_session_is_not_credited(): void
    {
        $this->signIn();
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($this->userId, time() + DAY_IN_SECONDS, 'logged_in', 'not-a-real-session');
        $this->inAdmin();

        $this->recorder->flush();

        $this->assertSame(['method' => 'other'], $this->uploadedRecords()[0]['credential']);
    }

    public function test_failed_login_keeps_real_usernames_and_hashes_anything_else(): void
    {
        wp_signon(['user_login' => 'editor', 'user_password' => 'wrong']);
        wp_signon(['user_login' => 'hunter2-typed-as-username', 'user_password' => 'wrong']);

        $this->recorder->flush();

        [$real, $unknown] = $this->uploadedRecords();
        $this->assertSame(['username' => 'editor'], $real['data']);
        $this->assertSame(['username_sha256' => hash('sha256', 'hunter2-typed-as-username')], $unknown['data']);
    }

    public function test_application_password_request_records_its_uuid_and_rest_calls(): void
    {
        [$password, $item] = WP_Application_Passwords::create_new_application_password($this->userId, ['name' => 'integration']);
        $this->allowApplicationPasswords();

        $user = wp_authenticate_application_password(null, 'editor', $password);
        $this->assertSame($this->userId, $user->ID);
        wp_set_current_user($this->userId);
        rest_do_request(new WP_REST_Request('GET', '/wp/v2/users/me'));

        $this->recorder->flush();

        $records = array_column($this->uploadedRecords(), null, 'event');
        $this->assertSame($item['uuid'], $records['application_password_created']['data']['uuid']);
        $this->assertSame(['method' => 'application_password', 'uuid' => $item['uuid']], $records['request']['credential']);
        $this->assertSame([['method' => 'GET', 'route' => '/wp/v2/users/me', 'id' => null]], $records['request']['data']['rest']);
    }

    public function test_rejected_application_password_is_recorded(): void
    {
        WP_Application_Passwords::create_new_application_password($this->userId, ['name' => 'integration']);
        $this->allowApplicationPasswords();
        $_SERVER['PHP_AUTH_USER'] = 'editor';

        wp_authenticate_application_password(null, 'editor', 'wrong wrong wrong wrong');
        $this->recorder->flush();

        $failed = array_column($this->uploadedRecords(), null, 'event')['application_password_failed'];
        $this->assertSame(['username' => 'editor', 'error' => 'incorrect_password'], $failed['data']);
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
        $this->inAdmin();
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
        wp_signon(['user_login' => 'editor', 'user_password' => 'wrong']);

        $this->recorder->flush();

        $this->assertSame([], $this->uploads());
    }

    public function test_cron_on_a_server_without_live_traffic_is_dropped(): void
    {
        // A staging restore: WP_HOME, and so HTTP_HOST, still says live.
        add_filter('wp_doing_cron', '__return_true');
        $this->log('access.log', self::line('stg-example-staging.kinsta.cloud'));
        (new \WP_User($this->userId))->set_role('editor');

        $this->recorder->flush();

        $this->assertSame([], $this->uploads());
    }

    public function test_cron_on_live_is_recorded(): void
    {
        add_filter('wp_doing_cron', '__return_true');
        $this->log('access.log', self::line('www.example.fi'));
        (new \WP_User($this->userId))->set_role('editor');

        $this->recorder->flush();

        $record = array_column($this->uploadedRecords(), null, 'event')['role_changed'];
        $this->assertSame('cron', $record['context']);
        $this->assertSame(['target_user_id' => $this->userId, 'role' => 'editor', 'old_roles' => ['administrator']], $record['data']);
    }

    public function test_security_changes_are_recorded(): void
    {
        wp_update_user(['ID' => $this->userId, 'user_email' => 'new@example.fi']);
        update_option('users_can_register', 1);
        do_action('activated_plugin', 'evil/evil.php');

        $this->recorder->flush();

        $events = array_column($this->uploadedRecords(), 'data', 'event');
        $this->assertSame(['email'], $events['credentials_changed']['fields']);
        $this->assertSame('users_can_register', $events['option_updated']['option']);
        $this->assertSame(['plugin' => 'evil/evil.php'], $events['plugin_activated']);
    }

    public function test_query_string_credentials_are_redacted_from_the_uri(): void
    {
        $this->signIn();
        $this->inAdmin();
        $_SERVER['REQUEST_URI'] = '/wp-json/wc/v3/orders?consumer_key=ck_1&consumer_secret=cs_2';

        $this->recorder->flush();

        $this->assertSame('/wp-json/wc/v3/orders?consumer_key=REDACTED&consumer_secret=REDACTED', $this->uploadedRecords()[0]['uri']);
    }

    public function test_failed_upload_goes_to_the_retry_queue(): void
    {
        wp_signon(['user_login' => 'editor', 'user_password' => 'wrong']);
        $this->respond(503);

        $this->recorder->flush();

        $this->assertCount(1, get_option('wp_audit_log_retry'));
    }

    public function test_hooks_fired_with_missing_arguments_do_not_fatal(): void
    {
        // Called directly: core's own listeners on these hooks fatal without
        // their arguments, which would hide whether ours do.
        $this->recorder->onLogin();
        $this->recorder->onProfileUpdated($this->userId);
        $this->recorder->onUpgrade();
        $this->assertSame('response', $this->recorder->onRestCall('response'));

        $this->recorder->flush();

        $this->assertSame('login', $this->uploadedRecords()[0]['event']);
    }
}
