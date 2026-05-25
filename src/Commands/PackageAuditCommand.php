<?php

namespace Sambenne\PackageSecurity\Commands;

use Illuminate\Contracts\Foundation\Application as LaravelApplication;
use Illuminate\Console\Command;
use Sambenne\PackageSecurity\Auditors\ComposerAuditor;
use Sambenne\PackageSecurity\Auditors\NpmAuditor;
use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\ConsoleRenderer;
use Sambenne\PackageSecurity\Reports\JsonRenderer;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;
use Throwable;

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
        $defaultPath = $this->defaultPath();
        $path = realpath((string) ($this->argument('path') ?: $defaultPath)) ?: (string) ($this->argument('path') ?: $defaultPath);
        $config = $this->packageConfig();

        $policy = RiskPolicy::fromArray($config, [
            'fail_on' => $this->option('fail-on') ?: null,
        ]);

        $report = new AuditReport($path);
        $runner = new NativeCommandRunner();

        foreach ($this->auditors($runner, $policy, $config) as $auditor) {
            $report->merge($auditor->audit($path));
        }

        $format = strtolower((string) $this->option('format'));

        if ($format === 'json') {
            $this->line((new JsonRenderer())->render($report));
        } else {
            (new ConsoleRenderer($this->output))->render($report);
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
    private function auditors(NativeCommandRunner $runner, RiskPolicy $policy, array $config): array
    {
        $composerOnly = (bool) $this->option('composer');
        $npmOnly = (bool) $this->option('npm');
        $auditConfig = is_array($config['audit'] ?? null) ? $config['audit'] : [];

        $composerEnabled = (bool) ($auditConfig['composer'] ?? true);
        $npmEnabled = (bool) ($auditConfig['npm'] ?? true);

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

    private function defaultPath(): string
    {
        try {
            if (function_exists('base_path')) {
                return base_path();
            }
        } catch (Throwable) {
            //
        }

        return getcwd() ?: '.';
    }

    /**
     * @return array<string, mixed>
     */
    private function packageConfig(): array
    {
        $fallback = require __DIR__ . '/../../config/package-security.php';

        try {
            if (function_exists('app')) {
                $app = app();

                if ($app instanceof LaravelApplication && $app->bound('config')) {
                    $config = $app->make('config')->get('package-security', []);

                    return is_array($config) ? array_replace_recursive($fallback, $config) : $fallback;
                }
            }
        } catch (Throwable) {
            //
        }

        return $fallback;
    }
}
