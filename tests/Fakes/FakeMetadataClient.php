<?php

namespace Sambenne\PackageSecurity\Tests\Fakes;

use DateTimeImmutable;
use Sambenne\PackageSecurity\Support\PackageMetadataClient;

class FakeMetadataClient extends PackageMetadataClient
{
    /**
     * @param array<string, DateTimeImmutable> $composerDates
     * @param array<string, DateTimeImmutable> $npmDates
     */
    public function __construct(
        private readonly array $composerDates = [],
        private readonly array $npmDates = [],
    ) {
    }

    public function composerPublishedAt(string $package, string $version): ?DateTimeImmutable
    {
        return $this->composerDates[$package . ':' . $version] ?? null;
    }

    public function npmPublishedAt(string $package, string $version): ?DateTimeImmutable
    {
        return $this->npmDates[$package . ':' . $version] ?? null;
    }
}
