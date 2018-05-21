my $app = sub {
    my ($environ) = @_;

    my $len = int($environ->{'CONTENT_LENGTH'});
    $environ->{'psgi.input'}->read(my $body, $len);

    my $version = join('', @{$environ->{'psgi.version'}});

    return ['200', [
        'Content-Type' => $environ->{'CONTENT_TYPE'},
        'Content-Length' => $len,
        'Request-Method' => $environ->{'REQUEST_METHOD'},
        'Request-Uri' => $environ->{'REQUEST_URI'},
        'Http-Host' => $environ->{'HTTP_HOST'},
        'Server-Protocol' => $environ->{'SERVER_PROTOCOL'},
        'Server-Software' => $environ->{'SERVER_SOFTWARE'},
        'Custom-Header' => $environ->{'HTTP_CUSTOM_HEADER'},
        'Psgi-Version' => $version,
        'Psgi-Url-Scheme' => $environ->{'psgi.url_scheme'},
        'Psgi-Multithread' => $environ->{'psgi.multithread'},
        'Psgi-Multiprocess' => $environ->{'psgi.multiprocess'},
        'Psgi-Run-Once' => $environ->{'psgi.run_once'},
        'Psgi-Nonblocking' => $environ->{'psgi.nonblocking'},
        'Psgi-Streaming' => $environ->{'psgi.streaming'}
    ], [$body]];
};
