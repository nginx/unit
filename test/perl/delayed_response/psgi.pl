my $app = sub {
    my ($environ) = @_;

    return sub {
        (my $responder = shift)->([200, [
            'Content-Type' => 'text/plain',
            'Content-Length' => '12'
        ], ["Hello World!"]]);
    }
};
