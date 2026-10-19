<?php

namespace GeneroWP\AuditLog;

use WP_User;

/**
 * Records who made each sensitive request and how they authenticated, plus a
 * fixed set of security events. What a request *read* comes from the access
 * log, joined on request time, IP and URI; this only adds what the access log
 * cannot see: the user, the credential, POST parameters and REST sub-requests.
 *
 * Content is never recorded, only identifiers.
 */
class Recorder
{
    /** Options whose changes alter who can get into the site. */
    private const WATCHED_OPTIONS = ['admin_email', 'default_role', 'home', 'siteurl', 'users_can_register'];

    /**
     * Background-job loopbacks that WordPress sends to itself with the current
     * user's cookie, every few seconds while a queue has work. They are still
     * in the access log; recording them here would only bury real requests.
     * WP_Background_Process names its actions wp_{blog_id}_{name}.
     */
    private const LOOPBACK_ACTIONS = '/^(as_async_request_queue_runner|wp_\d+_[a-z0-9_]+)$/';

    /** POST fields that carry the action or the IDs it acts on, never content. */
    private const POST_FIELDS = ['action', 'action2', 'export_form', 'id', 'lead', 'order', 'post', 'post_ID', 'user', 'users'];

    /** @var array<int, array<string, mixed>> */
    private array $events = [];

    /** @var array<int, array<string, mixed>> */
    private array $restCalls = [];

    /** @var array<string, mixed>|null */
    private ?array $credential = null;

    private ?string $loginToken = null;

    public function __construct(private Config $config, private Uploader $uploader) {}

    public function register(): void
    {
        add_action('application_password_did_authenticate', [$this, 'onApplicationPassword'], 10, 2);
        add_action('application_password_failed_authentication', [$this, 'onApplicationPasswordFailed']);
        add_action('wp_create_application_password', [$this, 'onApplicationPasswordCreated'], 10, 2);
        add_action('wp_delete_application_password', [$this, 'onApplicationPasswordDeleted'], 10, 2);

        add_action('set_logged_in_cookie', [$this, 'onLoggedInCookie'], 10, 6);
        add_action('wp_login', [$this, 'onLogin'], 10, 2);
        add_action('wp_login_failed', [$this, 'onLoginFailed']);
        add_action('wp_logout', [$this, 'onLogout']);
        add_action('retrieve_password', [$this, 'onPasswordResetRequested']);
        add_action('after_password_reset', [$this, 'onPasswordReset']);

        add_action('user_register', [$this, 'onUserCreated']);
        add_action('deleted_user', [$this, 'onUserDeleted']);
        add_action('set_user_role', [$this, 'onRoleChanged'], 10, 3);
        add_action('profile_update', [$this, 'onProfileUpdated'], 10, 2);
        add_action('activated_plugin', fn ($plugin = '') => $this->event('change', 'plugin_activated', ['plugin' => (string) $plugin]));
        add_action('deactivated_plugin', fn ($plugin = '') => $this->event('change', 'plugin_deactivated', ['plugin' => (string) $plugin]));
        add_action('upgrader_process_complete', [$this, 'onUpgrade'], 10, 2);
        add_action('switch_theme', fn ($name = '') => $this->event('change', 'theme_switched', ['theme' => (string) $name]));
        add_action('updated_option', [$this, 'onOptionUpdated'], 10, 3);

        add_action('woocommerce_order_status_changed', [$this, 'onOrderStatusChanged'], 10, 3);
        add_action('woocommerce_order_refunded', fn ($orderId = 0, $refundId = 0) => $this->event('change', 'order_refunded', [
            'order_id' => (int) $orderId,
            'refund_id' => (int) $refundId,
        ]), 10, 2);

        add_filter('rest_request_after_callbacks', [$this, 'onRestCall'], 10, 3);

        // After WordPress has flushed its output buffers, so the upload runs
        // once the response is already on its way to the visitor.
        add_action('shutdown', [$this, 'flush'], PHP_INT_MAX);
    }

    // Hook callbacks are deliberately untyped: another plugin firing one of
    // these actions with fewer or odd arguments must not fatal the request.

    public function onApplicationPassword($user = null, $item = []): void
    {
        $this->credential = ['method' => 'application_password', 'uuid' => $item['uuid'] ?? null];
    }

    public function onApplicationPasswordFailed($error = null): void
    {
        $this->event('auth', 'application_password_failed', self::attemptedUsername(
            (string) wp_unslash($_SERVER['PHP_AUTH_USER'] ?? ''),
        ) + [
            'error' => is_wp_error($error) ? $error->get_error_code() : null,
        ]);
    }

    public function onApplicationPasswordCreated($userId = 0, $item = []): void
    {
        $this->event('auth', 'application_password_created', ['target_user_id' => (int) $userId, 'uuid' => $item['uuid'] ?? null, 'name' => $item['name'] ?? null]);
    }

    public function onApplicationPasswordDeleted($userId = 0, $item = []): void
    {
        $this->event('auth', 'application_password_deleted', ['target_user_id' => (int) $userId, 'uuid' => $item['uuid'] ?? null]);
    }

    public function onLoggedInCookie($cookie = '', $expire = 0, $expiration = 0, $userId = 0, $scheme = '', $token = ''): void
    {
        $this->loginToken = is_string($token) && $token !== '' ? $token : null;
    }

    public function onLogin($login = '', $user = null): void
    {
        $user = $user instanceof WP_User ? $user : get_user_by('login', (string) $login);
        $this->event('auth', 'login', [
            'target_user_id' => $user ? $user->ID : null,
            'target_user_login' => $user ? $user->user_login : (string) $login,
            'session' => $this->loginToken ? hash('sha256', $this->loginToken) : null,
        ]);
    }

    public function onLoginFailed($username = ''): void
    {
        $this->event('auth', 'login_failed', self::attemptedUsername((string) $username));
    }

    public function onLogout($userId = 0): void
    {
        $this->event('auth', 'logout', ['target_user_id' => (int) $userId]);
    }

    public function onPasswordResetRequested($login = ''): void
    {
        $this->event('auth', 'password_reset_requested', self::attemptedUsername((string) $login));
    }

    public function onPasswordReset($user = null): void
    {
        $this->event('auth', 'password_reset', ['target_user_id' => $user instanceof WP_User ? $user->ID : null]);
    }

    public function onUserCreated($userId = 0): void
    {
        $user = get_userdata((int) $userId);
        $this->event('change', 'user_created', ['target_user_id' => (int) $userId, 'roles' => $user ? $user->roles : []]);
    }

    public function onUserDeleted($userId = 0): void
    {
        $this->event('change', 'user_deleted', ['target_user_id' => (int) $userId]);
    }

    public function onRoleChanged($userId = 0, $role = '', $oldRoles = []): void
    {
        $this->event('change', 'role_changed', ['target_user_id' => (int) $userId, 'role' => (string) $role, 'old_roles' => array_values((array) $oldRoles)]);
    }

    public function onProfileUpdated($userId = 0, $old = null): void
    {
        $new = get_userdata((int) $userId);
        if (! $new || ! $old instanceof WP_User) {
            return;
        }

        $changed = array_keys(array_filter([
            'email' => $new->user_email !== $old->user_email,
            'password' => $new->user_pass !== $old->user_pass,
            'login' => $new->user_login !== $old->user_login,
        ]));

        if ($changed) {
            $this->event('change', 'credentials_changed', ['target_user_id' => $userId, 'fields' => $changed]);
        }
    }

    public function onUpgrade($upgrader = null, $extra = []): void
    {
        $extra = (array) $extra;
        $this->event('change', 'upgrade', [
            'type' => $extra['type'] ?? null,
            'action' => $extra['action'] ?? null,
            'items' => $extra['plugins'] ?? $extra['themes'] ?? (isset($extra['plugin']) ? [$extra['plugin']] : []),
        ]);
    }

    public function onOptionUpdated($option = '', $old = null, $new = null): void
    {
        if (in_array($option, self::WATCHED_OPTIONS, true)) {
            $this->event('change', 'option_updated', ['option' => $option, 'old' => $old, 'new' => $new]);
        }
    }

    public function onOrderStatusChanged($orderId = 0, $from = '', $to = ''): void
    {
        $this->event('change', 'order_status_changed', ['order_id' => (int) $orderId, 'from' => (string) $from, 'to' => (string) $to]);
    }

    /**
     * Fires for every dispatched route, including each one inside a
     * /batch/v1 call, whose access-log line only shows the batch URL.
     */
    public function onRestCall($response, $handler = null, $request = null)
    {
        if (! $request instanceof \WP_REST_Request) {
            return $response;
        }

        $id = $request->get_param('id');
        $this->restCalls[] = [
            'method' => $request->get_method(),
            'route' => $request->get_route(),
            'id' => is_scalar($id) ? (string) $id : null,
        ];

        return $response;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function event(string $type, string $name, array $data = []): void
    {
        $this->events[] = ['type' => $type, 'event' => $name, 'data' => $data];
    }

    public function flush(): void
    {
        try {
            $this->send();
        } catch (\Throwable $e) {
            error_log('[wp-audit-log] '.$e->getMessage());
        }
    }

    /**
     * Requests with no allowed Host are dropped. For HTTP that is enough:
     * Kinsta routes by Host, so a live hostname never reaches staging. WP-CLI
     * and system cron take HTTP_HOST from WP_HOME instead, which a staging
     * restore copies from live, so those also need this server's own access
     * log to show live traffic.
     */
    private function send(): void
    {
        $host = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
        if (! $this->config->allowsHost($host)) {
            return;
        }

        if (! $this->events && ! is_user_logged_in()) {
            return;
        }

        if (self::context() !== 'http') {
            $dir = LogShipper::logDir($this->config);
            if (! $dir || ! LogShipper::servesHosts($dir, $this->config)) {
                return;
            }
        }

        $request = $this->requestRecord();
        $records = array_map(fn (array $event) => $event + $request, $this->events);

        if ($request['user_id'] && $this->isSensitiveRequest()) {
            $records[] = ['type' => 'request', 'event' => 'request', 'data' => [
                'params' => $this->postParams(),
                'rest' => $this->restCalls,
            ]] + $request;
        }

        if (! $records) {
            return;
        }

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }

        $body = implode("\n", array_map('wp_json_encode', $records))."\n";
        $object = sprintf(
            '%s/events/%s/%s.ndjson',
            $this->config->site,
            gmdate('Y-m-d/H'),
            gmdate('His').'-'.bin2hex(random_bytes(8)),
        );

        if ($this->uploader->put($object, $body, 'application/x-ndjson', 3) === Uploader::FAILED) {
            Retry::push($object, $body);
        }
    }

    /**
     * The fields every record carries. request_time, ip, method and uri are
     * what joins a record to its line in the access log.
     *
     * @return array<string, mixed>
     */
    private function requestRecord(): array
    {
        $user = wp_get_current_user();

        return [
            'v' => 1,
            'site' => $this->config->site,
            'blog_id' => get_current_blog_id(),
            'context' => self::context(),
            'time' => gmdate('Y-m-d\TH:i:s.v\Z'),
            'request_time' => gmdate('Y-m-d\TH:i:s', (int) ($_SERVER['REQUEST_TIME'] ?? time())).'Z',
            'host' => strtolower((string) ($_SERVER['HTTP_HOST'] ?? '')),
            'ip' => (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
            'user_agent' => (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''),
            'method' => (string) ($_SERVER['REQUEST_METHOD'] ?? ''),
            'uri' => Redactor::redact((string) ($_SERVER['REQUEST_URI'] ?? '')),
            'status' => http_response_code() ?: null,
            'user_id' => $user->ID ?: null,
            'user_login' => $user->ID ? $user->user_login : null,
            'credential' => $user->ID ? $this->credential() : null,
        ];
    }

    private static function context(): string
    {
        return match (true) {
            defined('WP_CLI') && WP_CLI => 'cli',
            wp_doing_cron() => 'cron',
            default => 'http',
        };
    }

    /**
     * Which credential authenticated the current user. A cookie or API key
     * the client sent is only credited when it really belongs to that user,
     * so a stray or forged one can't be mistaken for how they got in.
     *
     * @return array<string, mixed>
     */
    private function credential(): array
    {
        if ($this->credential) {
            return $this->credential;
        }

        $userId = get_current_user_id();

        $consumerKey = $_SERVER['PHP_AUTH_USER'] ?? $_GET['consumer_key'] ?? null;
        if (is_string($consumerKey) && str_starts_with($consumerKey, 'ck_')) {
            $keyId = $this->woocommerceKeyId($consumerKey, $userId);
            if ($keyId !== null) {
                return $this->credential = ['method' => 'woocommerce_api_key', 'key_id' => $keyId];
            }
        }

        if (defined('LOGGED_IN_COOKIE') && isset($_COOKIE[LOGGED_IN_COOKIE])) {
            $cookie = wp_unslash($_COOKIE[LOGGED_IN_COOKIE]);
            $parsed = wp_parse_auth_cookie($cookie, 'logged_in');
            if ($parsed && ! empty($parsed['token']) && wp_validate_auth_cookie($cookie, 'logged_in') === $userId) {
                // The same SHA-256 verifier WordPress stores in the session_tokens user meta.
                return $this->credential = ['method' => 'cookie', 'session' => hash('sha256', $parsed['token'])];
            }
        }

        return $this->credential = ['method' => 'other'];
    }

    private function woocommerceKeyId(string $consumerKey, int $userId): ?int
    {
        global $wpdb;

        if (! function_exists('wc_api_hash')) {
            return null;
        }

        $id = $wpdb->get_var($wpdb->prepare(
            "SELECT key_id FROM {$wpdb->prefix}woocommerce_api_keys WHERE consumer_key = %s AND user_id = %d",
            wc_api_hash(sanitize_text_field($consumerKey)),
            $userId,
        ));

        return $id === null ? null : (int) $id;
    }

    /**
     * People regularly type their password into the username field. Only
     * names of real accounts are kept in the clear; anything else is hashed,
     * which still lets repeated attempts with the same string be grouped.
     *
     * @return array<string, string>
     */
    private static function attemptedUsername(string $username): array
    {
        if ($username === '') {
            return ['username' => ''];
        }

        $exists = get_user_by('login', $username) ?: (is_email($username) ? get_user_by('email', $username) : false);

        return $exists ? ['username' => $username] : ['username_sha256' => hash('sha256', $username)];
    }

    private function isSensitiveRequest(): bool
    {
        $script = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));

        if ($script === 'admin-ajax.php' && preg_match(self::LOOPBACK_ACTIONS, (string) ($_REQUEST['action'] ?? ''))) {
            return false;
        }

        return is_admin()
            || (defined('REST_REQUEST') && REST_REQUEST)
            || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
            || in_array($script, ['admin-post.php', 'wp-login.php'], true)
            || ($this->credential()['method'] ?? null) !== 'cookie'
            || (function_exists('is_account_page') && is_account_page());
    }

    /**
     * @return array<string, mixed>
     */
    private function postParams(): array
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            return [];
        }

        $params = [];
        foreach (self::POST_FIELDS as $field) {
            $value = wp_unslash($_POST[$field] ?? null);
            if (is_scalar($value) && $value !== '') {
                $params[$field] = substr((string) $value, 0, 100);
            } elseif (is_array($value)) {
                $params[$field] = array_slice(array_values(array_filter($value, 'is_numeric')), 0, 500);
            }
        }

        return $params;
    }
}
