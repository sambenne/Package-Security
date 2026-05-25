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
        $policy = RiskPolicy::fromArray([
            'allow' => [
                'packages' => ['laravel/framework'],
                'advisories' => ['GHSA-1234'],
            ],
        ]);

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

    public function test_it_evaluates_license_policy(): void
    {
        $policy = RiskPolicy::fromArray([
            'licenses' => [
                'allow' => ['MIT'],
                'block' => ['GPL-3.0-only'],
                'block_unknown' => true,
            ],
        ]);

        $this->assertSame('medium', $policy->evaluateLicenses(['GPL-3.0-only'])['severity']);
        $this->assertSame('medium', $policy->evaluateLicenses(['Apache-2.0'])['severity']);
        $this->assertTrue($policy->evaluateLicenses([])['blocked']);
        $this->assertNull($policy->evaluateLicenses(['MIT']));
    }

    public function test_blocked_licenses_fail_when_all_options_are_blocked(): void
    {
        $policy = RiskPolicy::fromArray([
            'licenses' => [
                'block' => ['GPL-3.0-only'],
            ],
        ]);

        $this->assertSame('high', $policy->evaluateLicenses(['GPL-3.0-only'])['severity']);
        $this->assertTrue($policy->evaluateLicenses(['GPL-3.0-only'])['blocked']);
    }

    public function test_dual_licensed_packages_are_not_blocked_when_one_license_is_acceptable(): void
    {
        $policy = RiskPolicy::fromArray([
            'licenses' => [
                'block' => ['GPL-2.0-only', 'GPL-3.0-only'],
            ],
        ]);

        $this->assertNull($policy->evaluateLicenses(['BSD-3-Clause', 'GPL-2.0-only', 'GPL-3.0-only']));
    }

    public function test_strict_license_allow_list_accepts_any_allowed_option(): void
    {
        $policy = RiskPolicy::fromArray([
            'licenses' => [
                'allow' => ['MIT'],
                'block' => ['GPL-3.0-only'],
            ],
        ]);

        $this->assertNull($policy->evaluateLicenses(['MIT', 'GPL-3.0-only']));
    }
}
