use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Crypt::FNA',
    AUTHOR              => q{Mario Rossano aka Anak <software@netlogicalab.com>},
    VERSION_FROM        => 'lib/Crypt/FNA.pm',
    ABSTRACT_FROM       => 'lib/Crypt/FNA.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Crypt-FNA-*' },
);
