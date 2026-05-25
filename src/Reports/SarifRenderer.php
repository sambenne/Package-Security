<?php

namespace Sambenne\PackageSecurity\Reports;

class SarifRenderer
{
    public function render(AuditReport $report): string
    {
        $payload = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Package Security',
                            'informationUri' => 'https://github.com/sambenne/Package-Security',
                            'rules' => $this->rules($report),
                        ],
                    ],
                    'results' => array_map(
                        fn (Finding $finding): array => $this->result($finding),
                        $report->findings(),
                    ),
                ],
            ],
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '{}';
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function rules(AuditReport $report): array
    {
        $rules = [];

        foreach ($report->findings() as $finding) {
            $ruleId = $this->ruleId($finding);

            if (isset($rules[$ruleId])) {
                continue;
            }

            $rules[$ruleId] = [
                'id' => $ruleId,
                'name' => $this->ruleName($finding->type),
                'shortDescription' => [
                    'text' => $this->ruleName($finding->type),
                ],
                'defaultConfiguration' => [
                    'level' => $this->level($finding),
                ],
            ];
        }

        return array_values($rules);
    }

    /**
     * @return array<string, mixed>
     */
    private function result(Finding $finding): array
    {
        return [
            'ruleId' => $this->ruleId($finding),
            'level' => $this->level($finding),
            'message' => [
                'text' => sprintf('%s: %s', $finding->package, $finding->message),
            ],
            'locations' => [
                [
                    'physicalLocation' => [
                        'artifactLocation' => [
                            'uri' => $this->artifactUri($finding),
                        ],
                        'region' => [
                            'startLine' => 1,
                        ],
                    ],
                ],
            ],
            'properties' => [
                'ecosystem' => $finding->ecosystem,
                'package' => $finding->package,
                'severity' => $finding->severity,
                'blocked' => $finding->blocked,
                'advisory_id' => $finding->advisoryId,
                'url' => $finding->url,
            ],
        ];
    }

    private function ruleId(Finding $finding): string
    {
        return 'package-security/' . $finding->type;
    }

    private function ruleName(string $type): string
    {
        return ucwords(str_replace('-', ' ', $type));
    }

    private function level(Finding $finding): string
    {
        if ($finding->blocked || in_array($finding->severity, ['critical', 'high'], true)) {
            return 'error';
        }

        if (in_array($finding->severity, ['medium', 'moderate'], true)) {
            return 'warning';
        }

        return 'note';
    }

    private function artifactUri(Finding $finding): string
    {
        if ($finding->ecosystem === 'composer') {
            return 'composer.lock';
        }

        if ($finding->ecosystem === 'npm') {
            return 'package-lock.json';
        }

        return '.';
    }
}
