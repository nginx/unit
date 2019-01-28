use File::Basename;
use lib dirname (__FILE__);
use IOFake;

my $app = sub {
    my ($environ) = @_;

    my $io = IOFake->new($environ->{'psgi.errors'});

    return ['200', [ 'Content-Length' => '2' ], $io];
};
