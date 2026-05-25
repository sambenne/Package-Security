<?php

namespace Sambenne\PackageSecurity\Support;

class NativeCommandResult
{
    public function __construct(
        public readonly int $exitCode,
        public readonly string $output,
        public readonly string $error = '',
    ) {
    }

    public function successful(): bool
    {
        return $this->exitCode === 0;
    }
}
