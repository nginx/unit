my $app = sub {
    my ($environ) = @_;

    $len_1 = $environ->{'psgi.input'}->read(my $body_1, 4);
    $len_2 = $environ->{'psgi.input'}->read(my $body_2, 4);
    $len_3 = $environ->{'psgi.input'}->read(my $body_3, 2);

    return ['200', ['Content-Length' => $len_1 + $len_2 + $len_3],
        [$body_1 . $body_2 . $body_3]];
};
