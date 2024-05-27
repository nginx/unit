my $app = sub {
    my ($environ) = @_;

    return ['200', [
        'Content-Length' => 0,
        'Server-Port' => $environ->{'SERVER_PORT'}
    ], []];
};
