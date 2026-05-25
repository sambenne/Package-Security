<?php

namespace Sambenne\PackageSecurity\Tests;

use Sambenne\PackageSecurity\Risk\RiskPolicy;

class RiskPolicyTest extends TestCase
{
    public function test_it_blocks_severities_at_or_above_threshold(): void
    {
        $policy = new RiskPolicy('high', true, 7);

        $this->assertFalse($policy->blocksSeverity('medium'));
        $this->assertTrue($policy->blocksSeverity('high'));
        $this->assertTrue($policy->blocksSeverity('critical'));
    }

    public function test_it_allows_packages_and_advisories(): void
    {
        $policy = new RiskPolicy('high', true, 7, ['laravel/framework'], ['GHSA-1234']);

        $this->assertTrue($policy->allows('laravel/framework'));
        $this->assertTrue($policy->allows('vite', 'GHSA-1234'));
        $this->assertFalse($policy->allows('vite', 'GHSA-9999'));
    }
}
