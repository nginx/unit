use FileHandle;

my $app = sub {
    my ($environ) = @_;

    $environ->{'psgi.input'}->read(my $body, 1024);

    open my $io, "<", \$body;

    # This makes $io work as FileHandle under 5.8, .10 and .11.
    bless $io, 'FileHandle';

    $environ->{'psgix.input.buffered'} = 1;
    $environ->{'psgi.input'} = $io;

    return ['200', ['Content-Length' => length $body], [$body]];
};
