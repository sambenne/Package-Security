<?php

namespace Sambenne\PackageSecurity\Auditors;

use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\Finding;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;
use Sambenne\PackageSecurity\Support\PackageMetadataClient;

class NpmAuditor
{
    public function __construct(
        private readonly NativeCommandRunner $runner,
        private readonly RiskPolicy $policy,
        private readonly ?PackageMetadataClient $metadata = null,
    ) {
    }

    public function audit(string $path): AuditReport
    {
        $report = new AuditReport($path);

        if (! file_exists($path . DIRECTORY_SEPARATOR . 'package.json')) {
            return $report;
        }

        if (! file_exists($path . DIRECTORY_SEPARATOR . 'package-lock.json')) {
            $report->add(Finding::lockFileMissing('npm', 'package-lock.json', $this->policy->requireLockFiles));
            return $report;
        }

        $audit = $this->runner->run(['npm', 'audit', '--json'], $path);

        if (! $audit->successful() && trim($audit->output) === '') {
            $report->add(Finding::warning('npm', 'npm', 'npm audit could not run: ' . $audit->error));
            return $report;
        }

        $payload = json_decode($audit->output, true);

        if (! is_array($payload)) {
            $report->add(Finding::warning('npm', 'npm', 'npm audit returned output that could not be parsed.'));
            return $report;
        }

        foreach (($payload['vulnerabilities'] ?? []) as $package => $vulnerability) {
            if ($this->policy->allows((string) $package)) {
                continue;
            }

            $severity = strtolower((string) ($vulnerability['severity'] ?? 'high'));
            $via = $vulnerability['via'] ?? [];
            $title = $this->titleFromVia($via) ?: 'Security advisory';
            $advisoryId = $this->idFromVia($via);

            if ($this->policy->allows((string) $package, $advisoryId)) {
                continue;
            }

            $report->add(Finding::vulnerability(
                ecosystem: 'npm',
                package: (string) $package,
                severity: $severity,
                title: $title,
                advisoryId: $advisoryId,
                blocked: $this->policy->blocksSeverity($severity),
                url: $this->urlFromVia($via),
            ));
        }

        $this->auditLicenses($path, $report);
        $this->auditOutdatedPackages($path, $report);

        return $report;
    }

    private function auditLicenses(string $path, AuditReport $report): void
    {
        if (! $this->policy->licensesEnabled) {
            return;
        }

        $payload = json_decode((string) file_get_contents($path . DIRECTORY_SEPARATOR . 'package-lock.json'), true);

        if (! is_array($payload)) {
            return;
        }

        foreach ($this->npmPackages($payload) as $name => $version) {
            if ($this->policy->allows((string) $name)) {
                continue;
            }

            $licenses = $this->npmPackageLicenses((string) $name, (string) $version, $path);
            $decision = $this->policy->evaluateLicenses($licenses);

            if ($decision === null) {
                continue;
            }

            $report->add(Finding::licensePolicy(
                ecosystem: 'npm',
                package: (string) $name,
                licenses: $licenses,
                message: $decision['reason'],
                blocked: $decision['blocked'],
                severity: $decision['severity'],
            ));
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, string>
     */
    private function npmPackages(array $payload): array
    {
        $packages = [];

        if (is_array($payload['packages'] ?? null)) {
            foreach ($payload['packages'] as $path => $package) {
                if (! is_array($package) || $path === '') {
                    continue;
                }

                $name = (string) ($package['name'] ?? $this->packageNameFromLockPath((string) $path));
                $version = (string) ($package['version'] ?? '');

                if ($name !== '' && $version !== '') {
                    $packages[$name] = $version;
                }
            }
        }

        if ($packages === [] && is_array($payload['dependencies'] ?? null)) {
            foreach ($payload['dependencies'] as $name => $package) {
                if (is_array($package) && isset($package['version'])) {
                    $packages[(string) $name] = (string) $package['version'];
                }
            }
        }

        return $packages;
    }

    private function packageNameFromLockPath(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $nodeModules = '/node_modules/';
        $position = strrpos($path, $nodeModules);

        if ($position !== false) {
            return substr($path, $position + strlen($nodeModules));
        }

        if (str_starts_with($path, 'node_modules/')) {
            return substr($path, strlen('node_modules/'));
        }

        return basename($path);
    }

    /**
     * @return array<int, string>
     */
    private function npmPackageLicenses(string $name, string $version, string $path): array
    {
        $result = $this->runner->run(['npm', 'view', $name . '@' . $version, 'license', '--json'], $path);

        if (trim($result->output) === '') {
            return [];
        }

        $payload = json_decode($result->output, true);

        if (is_string($payload)) {
            return [$payload];
        }

        if (is_array($payload)) {
            return array_values(array_filter(array_map('strval', $payload)));
        }

        return [];
    }

    private function auditOutdatedPackages(string $path, AuditReport $report): void
    {
        if (! $this->policy->updatesEnabled && ! $this->policy->freshnessEnabled) {
            return;
        }

        $outdated = $this->runner->run(['npm', 'outdated', '--json'], $path);

        if (trim($outdated->output) === '') {
            return;
        }

        $payload = json_decode($outdated->output, true);

        if (! is_array($payload)) {
            return;
        }

        $metadata = $this->metadata ?? new PackageMetadataClient();

        foreach ($payload as $name => $package) {
            if (! is_array($package)) {
                continue;
            }

            $currentVersion = (string) ($package['current'] ?? '');
            $wantedVersion = (string) ($package['wanted'] ?? $package['latest'] ?? '');
            $candidateVersion = (string) ($package['latest'] ?? '');

            if ($currentVersion === '' || $candidateVersion === '' || $currentVersion === $candidateVersion || $this->policy->allows((string) $name)) {
                continue;
            }

            if ($this->policy->updatesEnabled) {
                $outsideConstraint = $wantedVersion !== '' && $wantedVersion !== $candidateVersion;

                $report->add(Finding::updateAvailable(
                    ecosystem: 'npm',
                    package: (string) $name,
                    currentVersion: $currentVersion,
                    wantedVersion: $wantedVersion !== '' ? $wantedVersion : $candidateVersion,
                    latestVersion: $candidateVersion,
                    severity: $outsideConstraint ? 'medium' : 'low',
                    reason: $outsideConstraint ? 'Latest is outside the declared dependency range.' : '',
                ));
            }

            if (! $this->policy->freshnessEnabled) {
                continue;
            }

            $publishedAt = $metadata->npmPublishedAt((string) $name, $candidateVersion);

            if ($publishedAt === null) {
                continue;
            }

            $decision = $this->policy->evaluateFreshness($publishedAt);

            if ($decision === null) {
                continue;
            }

            $report->add(Finding::freshRelease(
                ecosystem: 'npm',
                package: (string) $name,
                currentVersion: $currentVersion,
                candidateVersion: $candidateVersion,
                ageDays: $decision['age_days'],
                blocked: $decision['blocked'],
                severity: $decision['severity'],
            ));
        }
    }

    /**
     * @param array<int, mixed> $via
     */
    private function titleFromVia(array $via): string
    {
        foreach ($via as $item) {
            if (is_array($item) && isset($item['title'])) {
                return (string) $item['title'];
            }
        }

        return '';
    }

    /**
     * @param array<int, mixed> $via
     */
    private function idFromVia(array $via): string
    {
        foreach ($via as $item) {
            if (is_array($item) && isset($item['source'])) {
                return (string) $item['source'];
            }
        }

        return '';
    }

    /**
     * @param array<int, mixed> $via
     */
    private function urlFromVia(array $via): string
    {
        foreach ($via as $item) {
            if (is_array($item) && isset($item['url'])) {
                return (string) $item['url'];
            }
        }

        return '';
    }
}
