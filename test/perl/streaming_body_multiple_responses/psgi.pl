my $counter = 2;

my $app = sub {
    my $env = shift;

    return sub {
        my $responder = shift;
        $responder->([200, ['Content-Type'=>'text/plain'], [$counter++]]);
        $responder->([200, ['Content-Type'=>'text/plain'], [$counter++]]);
    };
};
