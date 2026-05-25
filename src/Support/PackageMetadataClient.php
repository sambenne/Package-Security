<?php

namespace Sambenne\PackageSecurity\Support;

use DateTimeImmutable;
use Throwable;

class PackageMetadataClient
{
    public function composerPublishedAt(string $package, string $version): ?DateTimeImmutable
    {
        $payload = $this->fetchJson(sprintf('https://repo.packagist.org/p2/%s.json', strtolower($package)));

        if (! is_array($payload)) {
            return null;
        }

        $versions = $payload['packages'][$package] ?? $payload['packages'][strtolower($package)] ?? [];

        if (! is_array($versions)) {
            return null;
        }

        foreach ($versions as $candidate) {
            if (! is_array($candidate) || ! isset($candidate['time'])) {
                continue;
            }

            if ($this->versionsMatch((string) ($candidate['version'] ?? ''), $version)) {
                return $this->date((string) $candidate['time']);
            }
        }

        return null;
    }

    public function npmPublishedAt(string $package, string $version): ?DateTimeImmutable
    {
        $payload = $this->fetchJson(sprintf('https://registry.npmjs.org/%s', rawurlencode($package)));

        if (! is_array($payload)) {
            return null;
        }

        $publishedAt = $payload['time'][$version] ?? null;

        return is_string($publishedAt) ? $this->date($publishedAt) : null;
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function fetchJson(string $url): ?array
    {
        try {
            $context = stream_context_create([
                'http' => [
                    'header' => "Accept: application/json\r\nUser-Agent: package-security\r\n",
                    'ignore_errors' => true,
                    'timeout' => 10,
                ],
            ]);

            $response = file_get_contents($url, false, $context);
        } catch (Throwable) {
            return null;
        }

        if (! is_string($response) || $response === '') {
            return null;
        }

        $payload = json_decode($response, true);

        return is_array($payload) ? $payload : null;
    }

    private function versionsMatch(string $knownVersion, string $candidateVersion): bool
    {
        return $knownVersion === $candidateVersion
            || ltrim($knownVersion, 'v') === ltrim($candidateVersion, 'v');
    }

    private function date(string $value): ?DateTimeImmutable
    {
        try {
            return new DateTimeImmutable($value);
        } catch (Throwable) {
            return null;
        }
    }
}
