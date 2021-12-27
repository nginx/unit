my $app = sub {
    my ($environ) = @_;

    $environ->{'psgi.input'}->read(my $body, 1024);
    $environ->{'psgi.input'}->close();

    return ['200', ['Content-Length' => length $body], [$body]];
};
