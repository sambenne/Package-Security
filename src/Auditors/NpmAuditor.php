<?php

namespace Sambenne\PackageSecurity\Auditors;

use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\Finding;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;

class NpmAuditor
{
    public function __construct(
        private readonly NativeCommandRunner $runner,
        private readonly RiskPolicy $policy,
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

        return $report;
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
