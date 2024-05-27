my $app = sub {
    my ($environ) = @_;

    my $result = $environ->{'psgi.errors'}->print('Error in application');

    return ['200', ['Content-Length' => '1'], [$result]];
};
