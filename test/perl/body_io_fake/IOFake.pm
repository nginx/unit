package IOFake;

sub new {
    my $class = shift;
    my $errors = shift;
    my $self = {};

    $self->{_count} = 2;
    $self->{_errors} = $errors;

    bless $self, $class;
    return $self;
}

sub getline() {
    my $self = shift;

    if ($self->{_count} > 0) {
        return $self->{_count}--;
    }

    $self->{_errors}->print('IOFake getline() $/ is ' . ${ $/ });

    return;
}

sub close() {
    my $self = shift;

    $self->{_errors}->print('IOFake close() called');
};

1;
