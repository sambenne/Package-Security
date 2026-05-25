<?php

namespace Sambenne\PackageSecurity\Tests;

use DateTimeImmutable;
use Sambenne\PackageSecurity\Auditors\ComposerAuditor;
use Sambenne\PackageSecurity\Auditors\NpmAuditor;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandResult;
use Sambenne\PackageSecurity\Tests\Fakes\FakeCommandRunner;
use Sambenne\PackageSecurity\Tests\Fakes\FakeMetadataClient;

class FreshnessAuditTest extends TestCase
{
    public function test_composer_auditor_blocks_fresh_update_candidates(): void
    {
        $path = $this->projectWithFiles([
            'composer.json' => '{}',
            'composer.lock' => '{}',
        ]);

        $auditor = new ComposerAuditor(
            new FakeCommandRunner([
                'composer audit --format=json' => new NativeCommandResult(0, '{"advisories":[],"abandoned":[]}'),
                'composer outdated --format=json' => new NativeCommandResult(1, '{"installed":[{"name":"vendor/package","version":"1.0.0","latest":"1.1.0"}]}'),
            ]),
            new RiskPolicy('high', true, true, 7, 2),
            new FakeMetadataClient(composerDates: [
                'vendor/package:1.1.0' => new DateTimeImmutable('-1 day'),
            ]),
        );

        $report = $auditor->audit($path);

        $this->assertTrue($report->hasBlockedFindings());
        $this->assertSame('update-available', $report->findings()[0]->type);
        $this->assertSame('fresh-release', $report->findings()[1]->type);
    }

    public function test_npm_auditor_warns_about_fresh_update_candidates(): void
    {
        $path = $this->projectWithFiles([
            'package.json' => '{}',
            'package-lock.json' => '{}',
        ]);

        $auditor = new NpmAuditor(
            new FakeCommandRunner([
                'npm audit --json' => new NativeCommandResult(0, '{"vulnerabilities":[]}'),
                'npm outdated --json' => new NativeCommandResult(1, '{"vite":{"current":"1.0.0","latest":"2.0.0"}}'),
            ]),
            new RiskPolicy('high', true, true, 7, 2),
            new FakeMetadataClient(npmDates: [
                'vite:2.0.0' => new DateTimeImmutable('-5 days'),
            ]),
        );

        $report = $auditor->audit($path);

        $this->assertFalse($report->hasBlockedFindings());
        $this->assertTrue($report->hasWarnings());
        $this->assertSame('update-available', $report->findings()[0]->type);
        $this->assertSame('fresh-release', $report->findings()[1]->type);
        $this->assertSame('medium', $report->findings()[1]->severity);
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
