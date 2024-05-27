my $app = sub {
    my ($environ) = @_;

    return ['200', [
        'Content-Length' => 0,
        'Set-Cookie' => 'tc=one,two,three',
        'Set-Cookie' => 'tc=four,five,six'
    ], []];
};
