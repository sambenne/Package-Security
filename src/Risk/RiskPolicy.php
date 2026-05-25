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
     * @param array<int, string> $allowedLicenses
     * @param array<int, string> $blockedLicenses
     */
    public function __construct(
        public readonly string $failOn,
        public readonly bool $requireLockFiles,
        public readonly bool $freshnessEnabled,
        public readonly int $freshnessWarnDays,
        public readonly int $freshnessBlockDays,
        public readonly bool $updatesEnabled = true,
        public readonly bool $licensesEnabled = true,
        public readonly bool $blockUnknownLicenses = false,
        private readonly array $allowedPackages = [],
        private readonly array $allowedAdvisories = [],
        private readonly array $allowedLicenses = [],
        private readonly array $blockedLicenses = [],
    ) {
    }

    /**
     * @param array<string, mixed> $config
     * @param array<string, mixed> $overrides
     */
    public static function fromArray(array $config, array $overrides = []): self
    {
        $allow = is_array($config['allow'] ?? null) ? $config['allow'] : [];
        $licenses = is_array($config['licenses'] ?? null) ? $config['licenses'] : [];
        $updates = is_array($config['updates'] ?? null) ? $config['updates'] : [];
        $freshness = is_array($config['freshness'] ?? null) ? $config['freshness'] : [];
        $legacyFreshnessDays = (int) ($config['freshness_days'] ?? 7);

        return new self(
            failOn: strtolower((string) ($overrides['fail_on'] ?? $config['fail_on'] ?? 'high')),
            requireLockFiles: (bool) ($config['require_lock_files'] ?? true),
            freshnessEnabled: (bool) ($freshness['enabled'] ?? true),
            freshnessWarnDays: (int) ($freshness['warn_days'] ?? $legacyFreshnessDays),
            freshnessBlockDays: (int) ($freshness['block_days'] ?? 0),
            updatesEnabled: (bool) ($updates['enabled'] ?? true),
            licensesEnabled: (bool) ($licenses['enabled'] ?? true),
            blockUnknownLicenses: (bool) ($licenses['block_unknown'] ?? false),
            allowedPackages: array_values((array) ($allow['packages'] ?? [])),
            allowedAdvisories: array_values((array) ($allow['advisories'] ?? [])),
            allowedLicenses: array_values((array) ($licenses['allow'] ?? [])),
            blockedLicenses: array_values((array) ($licenses['block'] ?? [])),
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
     * @param array<int, string> $licenses
     * @return array{blocked: bool, severity: string, reason: string}|null
     */
    public function evaluateLicenses(array $licenses): ?array
    {
        if (! $this->licensesEnabled) {
            return null;
        }

        $licenses = array_values(array_filter(array_map(
            static fn (string $license): string => trim($license),
            $licenses,
        )));

        if ($licenses === []) {
            return [
                'blocked' => $this->blockUnknownLicenses,
                'severity' => $this->blockUnknownLicenses ? 'high' : 'medium',
                'reason' => 'Package licence is unknown.',
            ];
        }

        foreach ($licenses as $license) {
            if (in_array($license, $this->blockedLicenses, true)) {
                return [
                    'blocked' => true,
                    'severity' => 'high',
                    'reason' => sprintf('Package uses blocked licence %s.', $license),
                ];
            }
        }

        if ($this->allowedLicenses !== []) {
            foreach ($licenses as $license) {
                if (! in_array($license, $this->allowedLicenses, true)) {
                    return [
                        'blocked' => false,
                        'severity' => 'medium',
                        'reason' => sprintf('Package licence %s is not in the allowed licence list.', $license),
                    ];
                }
            }
        }

        return null;
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
