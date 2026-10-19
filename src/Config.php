<?php

namespace GeneroWP\AuditLog;

class Config
{
    /**
     * @param  string[]  $hosts
     */
    public function __construct(
        public readonly string $environment,
        public readonly string $site,
        public readonly string $bucket,
        public readonly string $accessId,
        public readonly string $secret,
        public readonly array $hosts,
        public readonly ?string $logDir,
        public readonly ?string $chatWebhook,
    ) {}

    public static function fromEnvironment(): self
    {
        return new self(
            environment: (string) (self::value('WP_ENV') ?? ''),
            site: (string) (self::value('AUDIT_LOG_SITE') ?? ''),
            bucket: (string) (self::value('AUDIT_LOG_BUCKET') ?? 'genero-audit-logs'),
            accessId: (string) (self::value('AUDIT_LOG_ACCESS_ID') ?? ''),
            secret: (string) (self::value('AUDIT_LOG_SECRET') ?? ''),
            hosts: self::parseHosts((string) (self::value('AUDIT_LOG_HOSTS') ?? '')),
            logDir: self::value('AUDIT_LOG_DIR') ?: null,
            chatWebhook: self::value('AUDIT_LOG_CHAT_WEBHOOK') ?: null,
        );
    }

    /**
     * Restoring a Kinsta backup to staging, or copying .env into DDEV, carries
     * the live credentials along. The host allowlist is what keeps those copies
     * from writing into the live site's folder, so an empty list means inactive.
     */
    public function isActive(): bool
    {
        return $this->environment === 'production'
            && $this->site !== ''
            && $this->accessId !== ''
            && $this->secret !== ''
            && $this->hosts !== [];
    }

    public function allowsHost(string $host): bool
    {
        return in_array(strtolower($host), $this->hosts, true);
    }

    /**
     * @return string[]
     */
    public static function parseHosts(string $value): array
    {
        return array_values(array_filter(array_map(
            fn (string $host) => strtolower(trim($host)),
            explode(',', $value),
        )));
    }

    /**
     * Bedrock defines most settings as constants, but plain .env values only
     * exist as environment variables.
     */
    private static function value(string $name): ?string
    {
        if (defined($name)) {
            return (string) constant($name);
        }

        $value = $_ENV[$name] ?? $_SERVER[$name] ?? getenv($name);

        return $value === false ? null : (string) $value;
    }
}
