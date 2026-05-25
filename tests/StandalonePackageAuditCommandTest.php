<?php

namespace Sambenne\PackageSecurity\Tests;

use PHPUnit\Framework\TestCase;
use Sambenne\PackageSecurity\Commands\StandalonePackageAuditCommand;
use Symfony\Component\Console\Tester\CommandTester;

class StandalonePackageAuditCommandTest extends TestCase
{
    public function test_standalone_command_audits_a_path_without_manifests(): void
    {
        $tester = new CommandTester(new StandalonePackageAuditCommand());

        $exitCode = $tester->execute([
            'path' => sys_get_temp_dir(),
            '--format' => 'json',
            '--composer' => true,
        ]);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('"status": "passed"', $tester->getDisplay());
    }

    public function test_standalone_command_can_render_sarif(): void
    {
        $tester = new CommandTester(new StandalonePackageAuditCommand());

        $exitCode = $tester->execute([
            'path' => sys_get_temp_dir(),
            '--format' => 'sarif',
        ]);

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('"version": "2.1.0"', $tester->getDisplay());
    }
}
