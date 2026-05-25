# GitHub Actions Integration

Package Security can fail pull requests with CI exit codes and upload SARIF results to GitHub code scanning.

## Laravel Project

Use this workflow when the package is installed in a Laravel application.

```yaml
name: Dependency Risk Gate

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write

jobs:
  package-security:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          coverage: none
          tools: composer:v2

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: npm

      - name: Install PHP dependencies
        run: composer install --no-interaction --no-progress --prefer-dist

      - name: Install npm dependencies
        run: npm ci

      - name: Audit dependencies
        run: php artisan package:audit --ci --format=sarif > package-security.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: package-security.sarif
```

## Standalone PHP Project

Use this workflow when you want to run the Composer binary directly.

```yaml
name: Dependency Risk Gate

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write

jobs:
  package-security:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          coverage: none
          tools: composer:v2

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: npm

      - name: Install PHP dependencies
        run: composer install --no-interaction --no-progress --prefer-dist

      - name: Install npm dependencies
        run: npm ci

      - name: Audit dependencies
        run: vendor/bin/package-security --ci --format=sarif > package-security.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: package-security.sarif
```

## Console-Only Gate

If you do not want SARIF upload, use table output and let `--ci` control the exit code.

```yaml
- name: Audit dependencies
  run: vendor/bin/package-security --ci
```

Exit codes:

- `0` means no findings
- `1` means warnings only
- `2` means blocked findings

## Composer-Only or npm-Only

Use these when a repository only has one ecosystem.

```yaml
- name: Audit Composer dependencies
  run: vendor/bin/package-security --ci --composer
```

```yaml
- name: Audit npm dependencies
  run: vendor/bin/package-security --ci --npm
```

## Notes

- `security-events: write` is required for SARIF upload.
- The SARIF upload step uses `if: always()` so results are still uploaded when the audit blocks the build.
- Run `npm ci` before auditing npm dependencies so npm has a complete lockfile-backed install.
- Publish and tune `config/package-security.php` in Laravel apps before enforcing the gate on protected branches.
