my $app = sub {
    my ($environ) = @_;

    open my $io, '<file';

    return ['200', ['Content-Length' => 5], $io];
};
