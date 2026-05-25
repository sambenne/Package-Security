<?php

namespace Sambenne\PackageSecurity\Commands;

use Sambenne\PackageSecurity\Auditors\ComposerAuditor;
use Sambenne\PackageSecurity\Auditors\NpmAuditor;
use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\ConsoleRenderer;
use Sambenne\PackageSecurity\Reports\JsonRenderer;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class StandalonePackageAuditCommand extends Command
{
    protected static $defaultName = 'audit';

    protected function configure(): void
    {
        $this
            ->setName('audit')
            ->setDescription('Audit Composer and npm dependencies using a configurable risk gate.')
            ->setAliases(['package:audit'])
            ->addArgument('path', InputArgument::OPTIONAL, 'Project path to audit', getcwd() ?: '.')
            ->addOption('composer', null, InputOption::VALUE_NONE, 'Audit Composer dependencies only')
            ->addOption('npm', null, InputOption::VALUE_NONE, 'Audit npm dependencies only')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Minimum severity that blocks the audit')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: table or json', 'table')
            ->addOption('ci', null, InputOption::VALUE_NONE, 'Return CI exit codes: 0 pass, 1 warnings, 2 blocked');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $rawPath = (string) $input->getArgument('path');
        $path = realpath($rawPath) ?: $rawPath;
        $config = $this->packageConfig();

        $policy = RiskPolicy::fromArray($config, [
            'fail_on' => $input->getOption('fail-on') ?: null,
        ]);

        $report = new AuditReport($path);
        $runner = new NativeCommandRunner();

        foreach ($this->auditors($input, $runner, $policy, $config) as $auditor) {
            $report->merge($auditor->audit($path));
        }

        if (strtolower((string) $input->getOption('format')) === 'json') {
            $output->writeln((new JsonRenderer())->render($report));
        } else {
            (new ConsoleRenderer($output))->render($report);
        }

        if ($report->hasBlockedFindings()) {
            return 2;
        }

        if ($input->getOption('ci') && $report->hasWarnings()) {
            return 1;
        }

        return 0;
    }

    /**
     * @return array<int, ComposerAuditor|NpmAuditor>
     */
    private function auditors(InputInterface $input, NativeCommandRunner $runner, RiskPolicy $policy, array $config): array
    {
        $composerOnly = (bool) $input->getOption('composer');
        $npmOnly = (bool) $input->getOption('npm');
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

    /**
     * @return array<string, mixed>
     */
    private function packageConfig(): array
    {
        return require __DIR__ . '/../../config/package-security.php';
    }
}
