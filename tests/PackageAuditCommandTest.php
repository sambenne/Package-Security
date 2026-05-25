<?php

namespace Sambenne\PackageSecurity\Tests;

class PackageAuditCommandTest extends TestCase
{
    public function test_command_passes_when_no_manifests_are_present(): void
    {
        $this->artisan('package:audit', [
            'path' => sys_get_temp_dir(),
            '--format' => 'json',
        ])->assertExitCode(0);
    }
}
