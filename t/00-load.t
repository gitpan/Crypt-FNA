#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 2;

BEGIN {
    use_ok( 'Crypt::FNA' ) || print "Bail out!\n";
    use_ok( 'Crypt::FNA::Validation' ) || print "Bail out!\n";
}

diag( "Testing Crypt::FNA $Crypt::FNA::VERSION, Perl $], $^X" );
