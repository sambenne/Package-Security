<?php

namespace Sambenne\PackageSecurity\Reports;

use Symfony\Component\Console\Output\OutputInterface;

class ConsoleRenderer
{
    public function __construct(private readonly OutputInterface $output)
    {
    }

    public function render(AuditReport $report): void
    {
        $status = $report->hasBlockedFindings()
            ? '<error>BLOCKED</error>'
            : ($report->hasWarnings() ? '<comment>WARNINGS</comment>' : '<info>PASS</info>');

        $this->output->writeln(sprintf('Package Security: %s', $status));
        $this->output->writeln(sprintf('Path: %s', $report->path));
        $this->output->writeln('');

        if (! $report->hasWarnings()) {
            $this->output->writeln('<info>No dependency risks found.</info>');
            return;
        }

        foreach ($report->findings() as $finding) {
            $marker = $finding->blocked ? '<error>BLOCK</error>' : '<comment>WARN</comment>';
            $this->output->writeln(sprintf(
                '%s [%s] %s/%s %s: %s',
                $marker,
                $finding->severity,
                $finding->ecosystem,
                $finding->package,
                $finding->type,
                $finding->message,
            ));

            if ($finding->url !== '') {
                $this->output->writeln('  ' . $finding->url);
            }
        }
    }
}
