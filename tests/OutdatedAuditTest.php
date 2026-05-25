<?php

namespace Sambenne\PackageSecurity\Tests;

use Sambenne\PackageSecurity\Auditors\ComposerAuditor;
use Sambenne\PackageSecurity\Auditors\NpmAuditor;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandResult;
use Sambenne\PackageSecurity\Tests\Fakes\FakeCommandRunner;

class OutdatedAuditTest extends TestCase
{
    public function test_composer_auditor_reports_available_updates(): void
    {
        $path = $this->projectWithFiles([
            'composer.json' => '{}',
            'composer.lock' => '{}',
        ]);

        $auditor = new ComposerAuditor(
            new FakeCommandRunner([
                'composer audit --format=json' => new NativeCommandResult(0, '{"advisories":[],"abandoned":[]}'),
                'composer outdated --format=json' => new NativeCommandResult(1, '{"installed":[{"name":"vendor/package","version":"1.0.0","latest":"2.0.0","latest-status":"update-possible"}]}'),
            ]),
            new RiskPolicy('high', true, false, 7, 2),
        );

        $report = $auditor->audit($path);

        $this->assertSame('update-available', $report->findings()[0]->type);
        $this->assertSame('medium', $report->findings()[0]->severity);
        $this->assertStringContainsString('outside the current constraint', $report->findings()[0]->message);
    }

    public function test_npm_auditor_reports_latest_outside_declared_range(): void
    {
        $path = $this->projectWithFiles([
            'package.json' => '{}',
            'package-lock.json' => '{}',
        ]);

        $auditor = new NpmAuditor(
            new FakeCommandRunner([
                'npm audit --json' => new NativeCommandResult(0, '{"vulnerabilities":[]}'),
                'npm outdated --json' => new NativeCommandResult(1, '{"vite":{"current":"1.0.0","wanted":"1.2.0","latest":"2.0.0"}}'),
            ]),
            new RiskPolicy('high', true, false, 7, 2),
        );

        $report = $auditor->audit($path);

        $this->assertSame('update-available', $report->findings()[0]->type);
        $this->assertSame('medium', $report->findings()[0]->severity);
        $this->assertStringContainsString('outside the declared dependency range', $report->findings()[0]->message);
    }

    public function test_update_reporting_can_be_disabled(): void
    {
        $path = $this->projectWithFiles([
            'package.json' => '{}',
            'package-lock.json' => '{}',
        ]);

        $auditor = new NpmAuditor(
            new FakeCommandRunner([
                'npm audit --json' => new NativeCommandResult(0, '{"vulnerabilities":[]}'),
                'npm outdated --json' => new NativeCommandResult(1, '{"vite":{"current":"1.0.0","wanted":"1.2.0","latest":"2.0.0"}}'),
            ]),
            new RiskPolicy('high', true, false, 7, 2, false),
        );

        $report = $auditor->audit($path);

        $this->assertFalse($report->hasWarnings());
    }

    /**
     * @param array<string, string> $files
     */
    private function projectWithFiles(array $files): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'package-security-' . uniqid('', true);
        mkdir($path);

        foreach ($files as $file => $content) {
            file_put_contents($path . DIRECTORY_SEPARATOR . $file, $content);
        }

        return $path;
    }
}
