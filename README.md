# Package Security

Package Security is a Laravel dependency risk gate for Composer and npm projects.

It adds an artisan command that wraps the native package audit tools and normalises the results into one policy-driven report.

```bash
php artisan package:audit
```

Or run it as a standalone Composer binary:

```bash
vendor/bin/package-security audit
```

## Why

Composer and npm already know how to report known vulnerabilities. This package adds the missing application-level gate:

- one command for Composer and npm
- Laravel config for fail thresholds
- CI-friendly exit codes
- lock-file enforcement
- outdated package reporting
- release freshness quarantine for newly published update candidates
- allow lists for accepted risk
- JSON output for pipelines

## Installation

```bash
composer require sambenne/package-security --dev
```

Publish the config:

```bash
php artisan vendor:publish --tag=package-security-config
```

## Usage

Audit the current Laravel application:

```bash
php artisan package:audit
```

Audit the current directory without Laravel:

```bash
vendor/bin/package-security
```

Audit another project path:

```bash
php artisan package:audit ../another-project
vendor/bin/package-security ../another-project
```

Composer only:

```bash
php artisan package:audit --composer
```

npm only:

```bash
php artisan package:audit --npm
```

Fail on medium or worse:

```bash
php artisan package:audit --fail-on=medium
```

Return JSON:

```bash
php artisan package:audit --format=json
```

Use CI exit codes:

```bash
php artisan package:audit --ci
```

Exit codes:

- `0` pass
- `1` warnings only, when `--ci` is used
- `2` blocked findings

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

## Current Checks

Composer:

- requires `composer.lock` when enabled
- runs `composer audit --format=json`
- runs `composer outdated --format=json`
- reports vulnerabilities
- reports abandoned packages when Composer includes them
- reports available updates
- warns or blocks when the latest update candidate is newly published

npm:

- requires `package-lock.json` when enabled
- runs `npm audit --json`
- runs `npm outdated --json`
- reports vulnerabilities
- reports available updates
- warns or blocks when the latest update candidate is newly published

## Update Reporting

Package Security reports update candidates as `update-available` findings.

Composer updates use Composer's `latest-status` field:

- `semver-safe-update` is a low-severity warning
- `update-possible` is a medium-severity warning because it is outside the current constraint

npm updates compare `wanted` and `latest`:

- latest inside the declared range is low severity
- latest outside the declared range is medium severity

## Release Freshness

Fresh releases are not automatically bad, but they are higher risk because compromised packages are often caught shortly after publication.

By default, Package Security:

- blocks update candidates published less than 2 days ago
- warns about update candidates published less than 7 days ago

Composer release dates are read from Packagist metadata. npm release dates are read from the npm registry.

## Roadmap

- licence policy checks
- GitHub Actions example
- SARIF output
- standalone `vendor/bin/package-security` command

## Development

```bash
composer install
composer test
```

GitHub Actions runs the test matrix for Laravel 10, 11, and 12.

## License

MIT
