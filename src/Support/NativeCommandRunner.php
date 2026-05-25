<?php

namespace Sambenne\PackageSecurity\Support;

use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;

class NativeCommandRunner
{
    /**
     * @param array<int, string> $command
     */
    public function run(array $command, string $workingDirectory): NativeCommandResult
    {
        try {
            $process = new Process($command, $workingDirectory);
            $process->setTimeout(120);
            $process->run();

            return new NativeCommandResult(
                exitCode: $process->getExitCode() ?? 1,
                output: $process->getOutput(),
                error: $process->getErrorOutput(),
            );
        } catch (ExceptionInterface $exception) {
            return new NativeCommandResult(
                exitCode: 1,
                output: '',
                error: $exception->getMessage(),
            );
        }
    }
}
