use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Crypt::FNA',
    license             => 'perl',
    dist_author         => q{Mario Rossano aka Anak <software@netlogicalab.com>},
    dist_abstract       => q{Installation utility for a Crypt::FNA ver 0.03 - Fractal Numerical Algorithm by Mario Rossano aka Anak - http://www.netlogicalab.com - software@netlogicalab.com},
    dist_version_from   => 'lib/Crypt/FNA.pm',
    build_requires => {
        'Test::More' => 0,
    },
    add_to_cleanup      => [ 'Crypt-FNA-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
