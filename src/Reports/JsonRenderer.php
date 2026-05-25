<?php

namespace Sambenne\PackageSecurity\Reports;

class JsonRenderer
{
    public function render(AuditReport $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '{}';
    }
}
