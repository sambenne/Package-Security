<?php

namespace Sambenne\PackageSecurity\Tests;

use Sambenne\PackageSecurity\Reports\AuditReport;
use Sambenne\PackageSecurity\Reports\Finding;
use Sambenne\PackageSecurity\Reports\SarifRenderer;

class SarifRendererTest extends TestCase
{
    public function test_it_renders_findings_as_sarif_results(): void
    {
        $report = new AuditReport(sys_get_temp_dir());
        $report->add(Finding::vulnerability(
            ecosystem: 'composer',
            package: 'vendor/package',
            severity: 'high',
            title: 'Example advisory',
            advisoryId: 'GHSA-test',
            blocked: true,
            url: 'https://example.test/advisory',
        ));

        $payload = json_decode((new SarifRenderer())->render($report), true);

        $this->assertSame('2.1.0', $payload['version']);
        $this->assertSame('Package Security', $payload['runs'][0]['tool']['driver']['name']);
        $this->assertSame('package-security/vulnerability', $payload['runs'][0]['results'][0]['ruleId']);
        $this->assertSame('error', $payload['runs'][0]['results'][0]['level']);
        $this->assertSame('composer.lock', $payload['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']);
    }
}
