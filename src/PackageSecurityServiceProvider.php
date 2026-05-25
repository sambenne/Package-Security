<?php

namespace Sambenne\PackageSecurity;

use Illuminate\Support\ServiceProvider;
use Sambenne\PackageSecurity\Commands\PackageAuditCommand;

class PackageSecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/package-security.php', 'package-security');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/package-security.php' => config_path('package-security.php'),
            ], 'package-security-config');

            $this->commands([
                PackageAuditCommand::class,
            ]);
        }
    }
}
