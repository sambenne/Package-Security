<?php

namespace Sambenne\PackageSecurity\Reports;

class Finding
{
    public function __construct(
        public readonly string $ecosystem,
        public readonly string $package,
        public readonly string $type,
        public readonly string $severity,
        public readonly string $message,
        public readonly bool $blocked = false,
        public readonly string $advisoryId = '',
        public readonly string $url = '',
    ) {
    }

    public static function vulnerability(
        string $ecosystem,
        string $package,
        string $severity,
        string $title,
        string $advisoryId = '',
        bool $blocked = false,
        string $url = '',
    ): self {
        return new self(
            ecosystem: $ecosystem,
            package: $package,
            type: 'vulnerability',
            severity: $severity,
            message: $title,
            blocked: $blocked,
            advisoryId: $advisoryId,
            url: $url,
        );
    }

    public static function lockFileMissing(string $ecosystem, string $file, bool $blocked): self
    {
        return new self(
            ecosystem: $ecosystem,
            package: $file,
            type: 'missing-lock-file',
            severity: $blocked ? 'high' : 'low',
            message: sprintf('%s is missing; audit results may not reflect installed dependencies.', $file),
            blocked: $blocked,
        );
    }

    public static function warning(string $ecosystem, string $package, string $message): self
    {
        return new self(
            ecosystem: $ecosystem,
            package: $package,
            type: 'warning',
            severity: 'low',
            message: $message,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ecosystem' => $this->ecosystem,
            'package' => $this->package,
            'type' => $this->type,
            'severity' => $this->severity,
            'message' => $this->message,
            'blocked' => $this->blocked,
            'advisory_id' => $this->advisoryId,
            'url' => $this->url,
        ];
    }
}
