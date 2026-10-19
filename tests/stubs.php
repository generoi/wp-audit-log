<?php

// Minimal in-memory stand-ins for the WordPress functions the plugin calls,
// so its logic can be tested without a WordPress install. Test state lives in
// $GLOBALS['wp_stub'] and is reset by StubbedTestCase.

const HOUR_IN_SECONDS = 3600;

class WP_User
{
    public array $roles = [];

    public function __construct(public int $ID = 0, public string $user_login = '', public string $user_email = '', public string $user_pass = '') {}
}

class WP_Error
{
    public function __construct(private string $code = '') {}

    public function get_error_code(): string
    {
        return $this->code;
    }
}

class WP_REST_Request
{
    public function __construct(private string $method, private string $route, private array $params = []) {}

    public function get_method(): string
    {
        return $this->method;
    }

    public function get_route(): string
    {
        return $this->route;
    }

    public function get_param(string $key)
    {
        return $this->params[$key] ?? null;
    }
}

function wp_stub_reset(): void
{
    $GLOBALS['wp_stub'] = [
        'options' => [],
        'autoload' => [],
        'transients' => [],
        'requests' => [],
        'responses' => [],
        'hooks' => [],
        'users' => [],
        'current_user' => 0,
        'valid_cookie' => null,
        'multisite' => false,
        'admin' => false,
        'cron' => false,
    ];
}

function add_action(string $hook, callable $callback, int $priority = 10, int $args = 1): void
{
    $GLOBALS['wp_stub']['hooks'][$hook][] = $callback;
}

function add_filter(string $hook, callable $callback, int $priority = 10, int $args = 1): void
{
    add_action($hook, $callback, $priority, $args);
}

function get_option(string $name, $default = false)
{
    return $GLOBALS['wp_stub']['options'][$name] ?? $default;
}

function update_option(string $name, $value, $autoload = null): bool
{
    $GLOBALS['wp_stub']['options'][$name] = $value;
    $GLOBALS['wp_stub']['autoload'][$name] = $autoload;

    return true;
}

function get_site_option(string $name, $default = false)
{
    return get_option($name, $default);
}

function update_site_option(string $name, $value): bool
{
    return update_option($name, $value);
}

function delete_site_option(string $name): bool
{
    unset($GLOBALS['wp_stub']['options'][$name]);

    return true;
}

function get_site_transient(string $name)
{
    return $GLOBALS['wp_stub']['transients'][$name] ?? false;
}

function set_site_transient(string $name, $value, int $expiration = 0): bool
{
    $GLOBALS['wp_stub']['transients'][$name] = $value;

    return true;
}

function is_multisite(): bool
{
    return $GLOBALS['wp_stub']['multisite'];
}

/**
 * Responses are queued per test as status codes; 0 means a network error.
 */
function wp_remote_request(string $url, array $args = [])
{
    $GLOBALS['wp_stub']['requests'][] = ['url' => $url] + $args;
    $status = array_shift($GLOBALS['wp_stub']['responses']) ?? 200;

    return $status === 0 ? new WP_Error('http_request_failed') : ['response' => ['code' => $status]];
}

function wp_remote_post(string $url, array $args = [])
{
    return wp_remote_request($url, ['method' => 'POST'] + $args);
}

function wp_remote_retrieve_response_code($response): int
{
    return $response['response']['code'];
}

function is_wp_error($thing): bool
{
    return $thing instanceof WP_Error;
}

function wp_json_encode($data)
{
    return json_encode($data);
}

function wp_unslash($value)
{
    return $value;
}

function sanitize_text_field($value): string
{
    return (string) $value;
}

function is_email($value): bool
{
    return (bool) filter_var($value, FILTER_VALIDATE_EMAIL);
}

function get_user_by(string $field, $value)
{
    foreach ($GLOBALS['wp_stub']['users'] as $user) {
        if (($field === 'login' && $user->user_login === $value) || ($field === 'email' && $user->user_email === $value)) {
            return $user;
        }
    }

    return false;
}

function get_userdata(int $id)
{
    return $GLOBALS['wp_stub']['users'][$id] ?? false;
}

function wp_get_current_user(): WP_User
{
    return get_userdata($GLOBALS['wp_stub']['current_user']) ?: new WP_User;
}

function get_current_user_id(): int
{
    return $GLOBALS['wp_stub']['current_user'];
}

function is_user_logged_in(): bool
{
    return get_current_user_id() > 0;
}

function get_current_blog_id(): int
{
    return 1;
}

function wp_doing_cron(): bool
{
    return $GLOBALS['wp_stub']['cron'];
}

function is_admin(): bool
{
    return $GLOBALS['wp_stub']['admin'];
}

/**
 * Cookies in tests look like "<login>|<expiration>|<token>|<hmac>".
 */
function wp_parse_auth_cookie(string $cookie, string $scheme = '')
{
    $parts = explode('|', $cookie);

    return count($parts) === 4 ? ['username' => $parts[0], 'token' => $parts[2]] : false;
}

function wp_validate_auth_cookie(string $cookie = '', string $scheme = '')
{
    return $GLOBALS['wp_stub']['valid_cookie'] === $cookie ? get_current_user_id() : false;
}
