#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'Crypt::FNA' );
    use_ok( 'Crypt::FNA::Validation' );
}

diag( "Testing Crypt::FNA $Crypt::FNA::VERSION, Perl $], $^X" );
