<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Enabled Auditors
    |--------------------------------------------------------------------------
    */
    'audit' => [
        'composer' => true,
        'npm' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Risk Policy
    |--------------------------------------------------------------------------
    |
    | Vulnerabilities at or above fail_on become blocked findings.
    | Supported severities: low, moderate, medium, high, critical.
    |
    */
    'fail_on' => env('PACKAGE_SECURITY_FAIL_ON', 'high'),

    'require_lock_files' => true,

    /*
    |--------------------------------------------------------------------------
    | Update Reporting
    |--------------------------------------------------------------------------
    |
    | Reports packages where a newer version exists. These findings do not block
    | by default, but they help teams see update pressure alongside security risk.
    |
    */
    'updates' => [
        'enabled' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Licence Policy
    |--------------------------------------------------------------------------
    |
    | Composer licences are read from composer.lock. npm licences are read from
    | registry metadata for installed packages listed in package-lock.json.
    |
    */
    'licenses' => [
        'enabled' => true,
        'allow' => [],
        'block' => [
            'AGPL-1.0',
            'AGPL-1.0-only',
            'AGPL-1.0-or-later',
            'AGPL-3.0',
            'AGPL-3.0-only',
            'AGPL-3.0-or-later',
            'GPL-1.0',
            'GPL-1.0-only',
            'GPL-1.0-or-later',
            'GPL-2.0',
            'GPL-2.0-only',
            'GPL-2.0-or-later',
            'GPL-3.0',
            'GPL-3.0-only',
            'GPL-3.0-or-later',
        ],
        'block_unknown' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Release Freshness Quarantine
    |--------------------------------------------------------------------------
    |
    | New package versions are higher-risk immediately after publication. The
    | audit can warn or block when an available update is inside this window.
    |
    */
    'freshness' => [
        'enabled' => true,
        'warn_days' => 7,
        'block_days' => 2,
    ],

    /*
    |--------------------------------------------------------------------------
    | Allow Lists
    |--------------------------------------------------------------------------
    |
    | Add package names or advisory IDs here when a known risk is accepted.
    |
    */
    'allow' => [
        'packages' => [],
        'advisories' => [],
    ],
];
