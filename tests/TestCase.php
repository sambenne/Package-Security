<?php

namespace Sambenne\PackageSecurity\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Sambenne\PackageSecurity\PackageSecurityServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            PackageSecurityServiceProvider::class,
        ];
    }
}
