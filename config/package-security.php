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
