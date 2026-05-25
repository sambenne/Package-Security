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

    'freshness_days' => 7,

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
- reports vulnerabilities
- reports abandoned packages when Composer includes them

npm:

- requires `package-lock.json` when enabled
- runs `npm audit --json`
- reports vulnerabilities

## Roadmap

- release-age quarantine for newly published versions
- outdated package reporting
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
