<?php

namespace Sambenne\PackageSecurity\Reports;

class AuditReport
{
    /**
     * @var array<int, Finding>
     */
    private array $findings = [];

    public function __construct(public readonly string $path)
    {
    }

    public function add(Finding $finding): void
    {
        $this->findings[] = $finding;
    }

    public function merge(self $report): void
    {
        foreach ($report->findings() as $finding) {
            $this->add($finding);
        }
    }

    /**
     * @return array<int, Finding>
     */
    public function findings(): array
    {
        return $this->findings;
    }

    public function hasBlockedFindings(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->blocked) {
                return true;
            }
        }

        return false;
    }

    public function hasWarnings(): bool
    {
        return $this->findings !== [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'path' => $this->path,
            'status' => $this->hasBlockedFindings() ? 'blocked' : ($this->hasWarnings() ? 'warning' : 'passed'),
            'findings' => array_map(static fn (Finding $finding): array => $finding->toArray(), $this->findings),
        ];
    }
}
