use IO::Handle;

my $app = sub {
    my ($environ) = @_;

    my $io = IO::Handle->new();

    return ['200', [], $io];
};
