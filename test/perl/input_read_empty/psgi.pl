my $app = sub {
    my ($environ) = @_;

    $len = $environ->{'psgi.input'}->read(my $body, 1024);

    return ['200', ['Content-Length' => $len], [$body]];
};
