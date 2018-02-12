my $app = sub {
    my ($environ) = @_;

    my $len = int($environ->{'CONTENT_LENGTH'});
    $environ->{'psgi.input'}->read(my $body, $len);

    return ['200', [
        'Content-Type' => $environ->{'CONTENT_TYPE'},
        'Content-Length' => $len,
        'Request-Method' => $environ->{'REQUEST_METHOD'},
        'Request-Uri' => $environ->{'REQUEST_URI'},
        'Http-Host' => $environ->{'HTTP_HOST'},
        'Server-Protocol' => $environ->{'SERVER_PROTOCOL'},
        'Custom-Header' => $environ->{'HTTP_CUSTOM_HEADER'}
    ], [$body]];
};
