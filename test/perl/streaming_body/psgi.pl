my $app = sub {
    my ($environ) = @_;

    return sub {
      my $writer = (my $responder = shift)->([200, [
          'Content-Type' => 'text/plain',
          'Content-Length' => '12'
      ]]);

      $writer->write("Hello World!");
      $writer->close;
    };
};
