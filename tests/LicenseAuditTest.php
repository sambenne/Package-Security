<?php

namespace Sambenne\PackageSecurity\Tests;

use Sambenne\PackageSecurity\Auditors\ComposerAuditor;
use Sambenne\PackageSecurity\Auditors\NpmAuditor;
use Sambenne\PackageSecurity\Risk\RiskPolicy;
use Sambenne\PackageSecurity\Support\NativeCommandResult;
use Sambenne\PackageSecurity\Tests\Fakes\FakeCommandRunner;

class LicenseAuditTest extends TestCase
{
    public function test_composer_auditor_blocks_configured_licenses(): void
    {
        $path = $this->projectWithFiles([
            'composer.json' => '{}',
            'composer.lock' => json_encode([
                'packages' => [
                    [
                        'name' => 'vendor/copyleft',
                        'license' => ['GPL-3.0-only'],
                    ],
                ],
            ]),
        ]);

        $auditor = new ComposerAuditor(
            new FakeCommandRunner([
                'composer audit --format=json' => new NativeCommandResult(0, '{"advisories":[],"abandoned":[]}'),
                'composer outdated --format=json' => new NativeCommandResult(0, '{"installed":[]}'),
            ]),
            RiskPolicy::fromArray([
                'licenses' => [
                    'enabled' => true,
                    'block' => ['GPL-3.0-only'],
                    'block_unknown' => false,
                ],
                'freshness' => ['enabled' => false],
                'updates' => ['enabled' => false],
            ]),
        );

        $report = $auditor->audit($path);

        $this->assertTrue($report->hasBlockedFindings());
        $this->assertSame('license-policy', $report->findings()[0]->type);
    }

    public function test_npm_auditor_warns_for_unknown_licenses_by_default(): void
    {
        $path = $this->projectWithFiles([
            'package.json' => '{}',
            'package-lock.json' => json_encode([
                'packages' => [
                    '' => ['name' => 'app', 'version' => '1.0.0'],
                    'node_modules/mystery' => ['version' => '1.2.3'],
                ],
            ]),
        ]);

        $auditor = new NpmAuditor(
            new FakeCommandRunner([
                'npm audit --json' => new NativeCommandResult(0, '{"vulnerabilities":[]}'),
                'npm outdated --json' => new NativeCommandResult(0, '{}'),
                'npm view mystery@1.2.3 license --json' => new NativeCommandResult(0, ''),
            ]),
            RiskPolicy::fromArray([
                'licenses' => [
                    'enabled' => true,
                    'block' => [],
                    'block_unknown' => false,
                ],
                'freshness' => ['enabled' => false],
                'updates' => ['enabled' => false],
            ]),
        );

        $report = $auditor->audit($path);

        $this->assertFalse($report->hasBlockedFindings());
        $this->assertTrue($report->hasWarnings());
        $this->assertSame('license-policy', $report->findings()[0]->type);
        $this->assertSame('medium', $report->findings()[0]->severity);
    }

    public function test_npm_auditor_preserves_scoped_package_names_from_lock_paths(): void
    {
        $path = $this->projectWithFiles([
            'package.json' => '{}',
            'package-lock.json' => json_encode([
                'packages' => [
                    'node_modules/@scope/package' => ['version' => '1.2.3'],
                ],
            ]),
        ]);

        $auditor = new NpmAuditor(
            new FakeCommandRunner([
                'npm audit --json' => new NativeCommandResult(0, '{"vulnerabilities":[]}'),
                'npm outdated --json' => new NativeCommandResult(0, '{}'),
                'npm view @scope/package@1.2.3 license --json' => new NativeCommandResult(0, ''),
            ]),
            RiskPolicy::fromArray([
                'licenses' => [
                    'enabled' => true,
                    'block' => [],
                    'block_unknown' => false,
                ],
                'freshness' => ['enabled' => false],
                'updates' => ['enabled' => false],
            ]),
        );

        $report = $auditor->audit($path);

        $this->assertSame('@scope/package', $report->findings()[0]->package);
    }

    public function test_license_checks_can_be_disabled(): void
    {
        $path = $this->projectWithFiles([
            'composer.json' => '{}',
            'composer.lock' => json_encode([
                'packages' => [
                    [
                        'name' => 'vendor/copyleft',
                        'license' => ['GPL-3.0-only'],
                    ],
                ],
            ]),
        ]);

        $auditor = new ComposerAuditor(
            new FakeCommandRunner([
                'composer audit --format=json' => new NativeCommandResult(0, '{"advisories":[],"abandoned":[]}'),
            ]),
            RiskPolicy::fromArray([
                'licenses' => ['enabled' => false],
                'freshness' => ['enabled' => false],
                'updates' => ['enabled' => false],
            ]),
        );

        $this->assertFalse($auditor->audit($path)->hasWarnings());
    }

    /**
     * @param array<string, string|false> $files
     */
    private function projectWithFiles(array $files): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'package-security-' . uniqid('', true);
        mkdir($path);

        foreach ($files as $file => $content) {
            file_put_contents($path . DIRECTORY_SEPARATOR . $file, (string) $content);
        }

        return $path;
    }
}
