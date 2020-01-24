#!/usr/bin/perl 
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Cipher::Stream::Trivium;
use Data::Dumper;

my $T = Cipher::Stream::Trivium->new(key => '0110' x 20, iv => 3141562);

$T->init();
my $stream;

for (1..10000) {
  $stream = $T->next(64);
  print "Cryptostream: $stream\n";
}

