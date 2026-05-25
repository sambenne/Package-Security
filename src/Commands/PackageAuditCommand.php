<?php

namespace Sambenne\PackageSecurity\Commands;

use Illuminate\Console\Command;
use Sambenne\PackageSecurity\Auditors\ComposerAuditor;
use Sambenne\PackageSecurity\Auditors\NpmAuditor;
use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\ConsoleRenderer;
use Sambenne\PackageSecurity\Reports\JsonRenderer;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;

class PackageAuditCommand extends Command
{
    protected $signature = 'package:audit
        {path? : Project path to audit}
        {--composer : Audit Composer dependencies only}
        {--npm : Audit npm dependencies only}
        {--fail-on= : Minimum severity that blocks the audit}
        {--format=table : Output format: table or json}
        {--ci : Return CI exit codes: 0 pass, 1 warnings, 2 blocked}';

    protected $description = 'Audit Composer and npm dependencies using a configurable risk gate.';

    public function handle(): int
    {
        $path = realpath((string) ($this->argument('path') ?: base_path())) ?: (string) ($this->argument('path') ?: base_path());
        $policy = RiskPolicy::fromArray(config('package-security', []), [
            'fail_on' => $this->option('fail-on') ?: null,
        ]);

        $report = new AuditReport($path);
        $runner = new NativeCommandRunner();

        foreach ($this->auditors($runner, $policy) as $auditor) {
            $report->merge($auditor->audit($path));
        }

        $format = strtolower((string) $this->option('format'));

        if ($format === 'json') {
            $this->line(new JsonRenderer()->render($report));
        } else {
            new ConsoleRenderer($this->output)->render($report);
        }

        if ($report->hasBlockedFindings()) {
            return 2;
        }

        if ($this->option('ci') && $report->hasWarnings()) {
            return 1;
        }

        return 0;
    }

    /**
     * @return array<int, ComposerAuditor|NpmAuditor>
     */
    private function auditors(NativeCommandRunner $runner, RiskPolicy $policy): array
    {
        $composerOnly = (bool) $this->option('composer');
        $npmOnly = (bool) $this->option('npm');

        $composerEnabled = (bool) config('package-security.audit.composer', true);
        $npmEnabled = (bool) config('package-security.audit.npm', true);

        if ($composerOnly) {
            $npmEnabled = false;
            $composerEnabled = true;
        }

        if ($npmOnly) {
            $composerEnabled = false;
            $npmEnabled = true;
        }

        $auditors = [];

        if ($composerEnabled) {
            $auditors[] = new ComposerAuditor($runner, $policy);
        }

        if ($npmEnabled) {
            $auditors[] = new NpmAuditor($runner, $policy);
        }

        return $auditors;
    }
}
