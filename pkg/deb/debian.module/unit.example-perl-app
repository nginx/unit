#!/usr/bin/env perl

use Data::Dumper;

my $app = sub {
      my $env = shift;
      return [
          '200',
          [ 'Content-Type' => 'text/plain' ],
          [ "Hello from Unit, Perl $^V, environment:\n\n", Dumper($env) ],
      ];
};
