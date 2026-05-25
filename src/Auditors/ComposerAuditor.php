<?php

namespace Sambenne\PackageSecurity\Auditors;

use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\Finding;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;
use Sambenne\PackageSecurity\Support\PackageMetadataClient;

class ComposerAuditor
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

        if (! file_exists($path . DIRECTORY_SEPARATOR . 'composer.json')) {
            return $report;
        }

        if (! file_exists($path . DIRECTORY_SEPARATOR . 'composer.lock')) {
            $report->add(Finding::lockFileMissing('composer', 'composer.lock', $this->policy->requireLockFiles));
            return $report;
        }

        $audit = $this->runner->run(['composer', 'audit', '--format=json'], $path);

        if (! $audit->successful() && trim($audit->output) === '') {
            $report->add(Finding::warning('composer', 'composer', 'Composer audit could not run: ' . $audit->error));
            return $report;
        }

        $payload = json_decode($audit->output, true);

        if (! is_array($payload)) {
            $report->add(Finding::warning('composer', 'composer', 'Composer audit returned output that could not be parsed.'));
            return $report;
        }

        foreach (($payload['advisories'] ?? []) as $package => $advisories) {
            foreach ((array) $advisories as $advisory) {
                $id = (string) ($advisory['advisoryId'] ?? $advisory['cve'] ?? $advisory['link'] ?? '');

                if ($this->policy->allows($package, $id)) {
                    continue;
                }

                $severity = strtolower((string) ($advisory['severity'] ?? 'high'));
                $report->add(Finding::vulnerability(
                    ecosystem: 'composer',
                    package: (string) $package,
                    severity: $severity,
                    title: (string) ($advisory['title'] ?? 'Security advisory'),
                    advisoryId: $id,
                    blocked: $this->policy->blocksSeverity($severity),
                    url: (string) ($advisory['link'] ?? ''),
                ));
            }
        }

        foreach (($payload['abandoned'] ?? []) as $package => $replacement) {
            if ($this->policy->allows((string) $package)) {
                continue;
            }

            $message = $replacement
                ? sprintf('Package is abandoned; suggested replacement: %s', $replacement)
                : 'Package is abandoned.';

            $report->add(Finding::warning('composer', (string) $package, $message));
        }

        $this->auditOutdatedPackages($path, $report);

        return $report;
    }

    private function auditOutdatedPackages(string $path, AuditReport $report): void
    {
        if (! $this->policy->updatesEnabled && ! $this->policy->freshnessEnabled) {
            return;
        }

        $outdated = $this->runner->run(['composer', 'outdated', '--format=json'], $path);

        if (trim($outdated->output) === '') {
            return;
        }

        $payload = json_decode($outdated->output, true);

        if (! is_array($payload)) {
            return;
        }

        $metadata = $this->metadata ?? new PackageMetadataClient();

        foreach (($payload['installed'] ?? []) as $package) {
            if (! is_array($package)) {
                continue;
            }

            $name = (string) ($package['name'] ?? '');
            $currentVersion = (string) ($package['version'] ?? '');
            $candidateVersion = (string) ($package['latest'] ?? '');
            $latestStatus = (string) ($package['latest-status'] ?? '');

            if ($name === '' || $currentVersion === '' || $candidateVersion === '' || $this->policy->allows($name)) {
                continue;
            }

            if ($this->policy->updatesEnabled) {
                $report->add(Finding::updateAvailable(
                    ecosystem: 'composer',
                    package: $name,
                    currentVersion: $currentVersion,
                    wantedVersion: $candidateVersion,
                    latestVersion: $candidateVersion,
                    severity: $latestStatus === 'update-possible' ? 'medium' : 'low',
                    reason: $this->composerUpdateReason($latestStatus),
                ));
            }

            if (! $this->policy->freshnessEnabled) {
                continue;
            }

            $publishedAt = $metadata->composerPublishedAt($name, $candidateVersion);

            if ($publishedAt === null) {
                continue;
            }

            $decision = $this->policy->evaluateFreshness($publishedAt);

            if ($decision === null) {
                continue;
            }

            $report->add(Finding::freshRelease(
                ecosystem: 'composer',
                package: $name,
                currentVersion: $currentVersion,
                candidateVersion: $candidateVersion,
                ageDays: $decision['age_days'],
                blocked: $decision['blocked'],
                severity: $decision['severity'],
            ));
        }
    }

    private function composerUpdateReason(string $latestStatus): string
    {
        return match ($latestStatus) {
            'semver-safe-update' => 'Composer reports this as a semver-safe update.',
            'update-possible' => 'Composer reports this as an update outside the current constraint.',
            default => '',
        };
    }
}
