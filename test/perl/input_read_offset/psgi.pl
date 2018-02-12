my $app = sub {
    my ($environ) = @_;

    $environ->{'psgi.input'}->read(my $body, 4, 4);

    return ['200', ['Content-Length' => 4], [$body]];
};
