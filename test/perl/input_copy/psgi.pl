my $app = sub {
    my ($environ) = @_;

    open(my $fh, ">&", $environ->{'psgi.input'});

    my $len = int($environ->{'CONTENT_LENGTH'});
    $fh->read(my $body, $len);

    return ['200', ['Content-Length' => $len], [$body]];
};
