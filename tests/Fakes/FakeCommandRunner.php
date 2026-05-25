<?php

namespace Sambenne\PackageSecurity\Tests\Fakes;

use Sambenne\PackageSecurity\Support\NativeCommandResult;
use Sambenne\PackageSecurity\Support\NativeCommandRunner;

class FakeCommandRunner extends NativeCommandRunner
{
    /**
     * @param array<string, NativeCommandResult> $results
     */
    public function __construct(private readonly array $results)
    {
    }

    public function run(array $command, string $workingDirectory): NativeCommandResult
    {
        return $this->results[implode(' ', $command)] ?? new NativeCommandResult(0, '{}');
    }
}
