<?php

namespace Sambenne\PackageSecurity\Tests;

use DateTimeImmutable;
use Sambenne\PackageSecurity\Risk\RiskPolicy;

class RiskPolicyTest extends TestCase
{
    public function test_it_blocks_severities_at_or_above_threshold(): void
    {
        $policy = new RiskPolicy('high', true, true, 7, 2);

        $this->assertFalse($policy->blocksSeverity('medium'));
        $this->assertTrue($policy->blocksSeverity('high'));
        $this->assertTrue($policy->blocksSeverity('critical'));
    }

    public function test_it_allows_packages_and_advisories(): void
    {
        $policy = new RiskPolicy('high', true, true, 7, 2, ['laravel/framework'], ['GHSA-1234']);

        $this->assertTrue($policy->allows('laravel/framework'));
        $this->assertTrue($policy->allows('vite', 'GHSA-1234'));
        $this->assertFalse($policy->allows('vite', 'GHSA-9999'));
    }

    public function test_it_evaluates_fresh_release_windows(): void
    {
        $policy = new RiskPolicy('high', true, true, 7, 2);
        $now = new DateTimeImmutable('2026-05-25T12:00:00+00:00');

        $blocked = $policy->evaluateFreshness(new DateTimeImmutable('2026-05-24T12:00:00+00:00'), $now);
        $warned = $policy->evaluateFreshness(new DateTimeImmutable('2026-05-20T12:00:00+00:00'), $now);
        $ignored = $policy->evaluateFreshness(new DateTimeImmutable('2026-05-01T12:00:00+00:00'), $now);

        $this->assertSame(['blocked' => true, 'severity' => 'high', 'age_days' => 1], $blocked);
        $this->assertSame(['blocked' => false, 'severity' => 'medium', 'age_days' => 5], $warned);
        $this->assertNull($ignored);
    }
}
