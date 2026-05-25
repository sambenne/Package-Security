# Package Security

[![Tests](https://github.com/sambenne/Package-Security/actions/workflows/tests.yml/badge.svg)](https://github.com/sambenne/Package-Security/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![PHP](https://img.shields.io/badge/php-%5E8.2-777bb4.svg)](composer.json)
[![Laravel](https://img.shields.io/badge/laravel-10%20%7C%2011%20%7C%2012-ff2d20.svg)](composer.json)

Package Security is a Laravel and Composer CLI dependency risk gate for Composer and npm projects.

It wraps the native package audit tools, adds policy checks, and produces table, JSON, or SARIF reports for local development and CI.

```bash
php artisan package:audit
vendor/bin/package-security
```

## Quick Start

Install in a Laravel or PHP project:

```bash
composer require sambenne/package-security --dev
```

For Laravel apps, publish the config:

```bash
php artisan vendor:publish --tag=package-security-config
```

Run the audit:

```bash
php artisan package:audit
```

Or use the standalone binary:

```bash
vendor/bin/package-security
```

Use CI mode to fail builds:

```bash
vendor/bin/package-security --ci
```

## Features

| Feature | Composer | npm |
|---|---:|---:|
| Known vulnerabilities | Yes | Yes |
| Lock-file enforcement | Yes | Yes |
| Available update reporting | Yes | Yes |
| Fresh release quarantine | Yes | Yes |
| Licence policy checks | Yes | Yes |
| JSON output | Yes | Yes |
| SARIF output | Yes | Yes |
| Laravel artisan command | Yes | Yes |
| Standalone Composer binary | Yes | Yes |

## Commands

Audit the current project:

```bash
php artisan package:audit
vendor/bin/package-security
```

Audit another project path:

```bash
php artisan package:audit ../another-project
vendor/bin/package-security ../another-project
```

Limit to one ecosystem:

```bash
php artisan package:audit --composer
php artisan package:audit --npm
```

Fail on medium or worse vulnerabilities:

```bash
php artisan package:audit --fail-on=medium
```

Render machine-readable reports:

```bash
php artisan package:audit --format=json
php artisan package:audit --format=sarif
vendor/bin/package-security --format=sarif
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | No findings, or warnings without `--ci` |
| `1` | Warnings only, when `--ci` is used |
| `2` | Blocked findings |

## What It Checks

Composer:

- requires `composer.lock` when enabled
- runs `composer audit --format=json`
- runs `composer outdated --format=json`
- reports vulnerabilities
- reports abandoned packages when Composer includes them
- checks licences from `composer.lock`
- reports available updates
- warns or blocks when an update candidate is newly published

npm:

- requires `package-lock.json` when enabled
- runs `npm audit --json`
- runs `npm outdated --json`
- reports vulnerabilities
- checks licences from npm registry metadata
- reports available updates
- warns or blocks when an update candidate is newly published

## Config

```php
return [
    'audit' => [
        'composer' => true,
        'npm' => true,
    ],

    'fail_on' => 'high',

    'require_lock_files' => true,

    'updates' => [
        'enabled' => true,
    ],

    'licenses' => [
        'enabled' => true,
        'allow' => [],
        'block' => [
            'AGPL-3.0-only',
            'AGPL-3.0-or-later',
            'GPL-2.0-only',
            'GPL-2.0-or-later',
            'GPL-3.0-only',
            'GPL-3.0-or-later',
        ],
        'block_unknown' => false,
    ],

    'freshness' => [
        'enabled' => true,
        'warn_days' => 7,
        'block_days' => 2,
    ],

    'allow' => [
        'packages' => [],
        'advisories' => [],
    ],
];
```

## Policy Details

Package Security reports update candidates as `update-available` findings.

Composer updates use Composer's `latest-status` field:

- `semver-safe-update` is a low-severity warning
- `update-possible` is a medium-severity warning because it is outside the current constraint

npm updates compare `wanted` and `latest`:

- latest inside the declared range is low severity
- latest outside the declared range is medium severity

Fresh releases are not automatically bad, but they are higher risk because compromised packages are often caught shortly after publication.

By default, Package Security:

- blocks update candidates published less than 2 days ago
- warns about update candidates published less than 7 days ago

Composer release dates are read from Packagist metadata. npm release dates are read from the npm registry.

Composer licences are read from `composer.lock`. npm licences are resolved with:

```bash
npm view package@version license --json
```

By default, Package Security blocks common GPL and AGPL identifiers and warns on unknown licences. Set `licenses.allow` to enforce a strict allow-list, or set `licenses.block_unknown` to `true` if unknown licences should fail CI.

## GitHub Actions

SARIF output can be uploaded to GitHub code scanning:

```yaml
- name: Audit dependencies
  run: vendor/bin/package-security --ci --format=sarif > package-security.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: package-security.sarif
```

For full copy-paste workflows, see [GitHub Actions Integration](docs/github-actions.md).

## Development

```bash
composer install
composer test
```

GitHub Actions runs the test matrix for Laravel 10, 11, and 12.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE.md](LICENSE.md).
