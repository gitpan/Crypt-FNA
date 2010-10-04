#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'Crypt::FNA' ) || print "Bail out!
";
    use_ok( 'Crypt::FNA::Validation' ) || print "Bail out!
";
}

diag( "Testing Crypt::FNA $Crypt::FNA::VERSION, Perl $], $^X" );
