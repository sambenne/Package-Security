<?php

namespace Sambenne\PackageSecurity\Risk;

use DateTimeImmutable;
use DateTimeInterface;

class RiskPolicy
{
    private const SEVERITY_WEIGHT = [
        'low' => 1,
        'moderate' => 2,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    /**
     * @param array<int, string> $allowedPackages
     * @param array<int, string> $allowedAdvisories
     */
    public function __construct(
        public readonly string $failOn,
        public readonly bool $requireLockFiles,
        public readonly bool $freshnessEnabled,
        public readonly int $freshnessWarnDays,
        public readonly int $freshnessBlockDays,
        private readonly array $allowedPackages = [],
        private readonly array $allowedAdvisories = [],
    ) {
    }

    /**
     * @param array<string, mixed> $config
     * @param array<string, mixed> $overrides
     */
    public static function fromArray(array $config, array $overrides = []): self
    {
        $allow = is_array($config['allow'] ?? null) ? $config['allow'] : [];
        $freshness = is_array($config['freshness'] ?? null) ? $config['freshness'] : [];
        $legacyFreshnessDays = (int) ($config['freshness_days'] ?? 7);

        return new self(
            failOn: strtolower((string) ($overrides['fail_on'] ?? $config['fail_on'] ?? 'high')),
            requireLockFiles: (bool) ($config['require_lock_files'] ?? true),
            freshnessEnabled: (bool) ($freshness['enabled'] ?? true),
            freshnessWarnDays: (int) ($freshness['warn_days'] ?? $legacyFreshnessDays),
            freshnessBlockDays: (int) ($freshness['block_days'] ?? 0),
            allowedPackages: array_values((array) ($allow['packages'] ?? [])),
            allowedAdvisories: array_values((array) ($allow['advisories'] ?? [])),
        );
    }

    public function blocksSeverity(string $severity): bool
    {
        $severity = strtolower($severity);
        $threshold = self::SEVERITY_WEIGHT[$this->failOn] ?? self::SEVERITY_WEIGHT['high'];

        return (self::SEVERITY_WEIGHT[$severity] ?? self::SEVERITY_WEIGHT['high']) >= $threshold;
    }

    public function allows(string $package, string $advisoryId = ''): bool
    {
        if (in_array($package, $this->allowedPackages, true)) {
            return true;
        }

        return $advisoryId !== '' && in_array($advisoryId, $this->allowedAdvisories, true);
    }

    /**
     * @return array{blocked: bool, severity: string, age_days: int}|null
     */
    public function evaluateFreshness(DateTimeInterface $publishedAt, ?DateTimeInterface $now = null): ?array
    {
        if (! $this->freshnessEnabled) {
            return null;
        }

        $now ??= new DateTimeImmutable();
        $ageDays = max(0, (int) $publishedAt->diff($now)->format('%a'));

        if ($this->freshnessBlockDays > 0 && $ageDays < $this->freshnessBlockDays) {
            return [
                'blocked' => true,
                'severity' => 'high',
                'age_days' => $ageDays,
            ];
        }

        if ($this->freshnessWarnDays > 0 && $ageDays < $this->freshnessWarnDays) {
            return [
                'blocked' => false,
                'severity' => 'medium',
                'age_days' => $ageDays,
            ];
        }

        return null;
    }
}
