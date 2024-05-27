my $app = sub {
    my ($environ) = @_;

    sleep int($environ->{'HTTP_X_DELAY'});

    return ['200', [
        'Content-Length' => 0,
        'Psgi-Multithread' => $environ->{'psgi.multithread'},
        'X-Thread' => $environ->{'psgi.input'}
    ], []];
};
