package Cipher::Stream::Trivium;

use 5.024001;
use strict;
use warnings;
use Bit::Vector::Overload;

our @ISA = qw();
our $VERSION = '0.1.0';

sub new {
    my $class = shift;
    my $IV = shift;  #Initialization Vector, 80 leftmost bits of A
    my $key = shift; #key, 80 leftmost bits of B
    my $self = {
        # Shift Registers; 93, 84 and 111 bits
        A => Bit::Vector->new(93),
        B => Bit::Vector->new(84),
        C => Bit::Vector->new_Dec(111,7)
    };
    bless $self,$class;
}

sub generate {
    my $self = shift;
    $self->{out}->{A} = $self->{C}->contains(112 - 65) ^ $self->{C}->contains(112 - 110) ^ 
               ($self->{C}->contains(112 - 109) & $self->{C}->contains(112 - 108)) ^ $self->{A}->contains(94 - 68);
    $self->{out}->{B} = $self->{A}->contains(94 - 65) ^ $self->{A}->contains(94 - 92) ^ 
               ($self->{A}->contains(94 - 91) & $self->{A}->contains(94 - 90)) ^ $self->{B}->contains(85 - 77);
    $self->{out}->{C} = $self->{B}->contains(85 - 68) ^ $self->{B}->contains(85 - 83) ^ 
               ($self->{B}->contains(85 - 82) & $self->{B}->contains(81)) ^ $self->{C}->contains(112 - 86);
    $self->{out}->{R} = $self->{C}->contains(112 - 65) & $self->{C}->contains(112 - 110) ^
              $self->{A}->contains(94 - 65) & $self->{A}->contains(94 - 92) ^
              $self->{B}->contains(85 - 68) & $self->{B}->contains(85 - 83);

    ## shifting ##
    $self->{$_}->Move_Right(1) for 'A','B','C';
    $self->{$_}->MSB($self->{out}->{$_}) for 'A','B','C';
}

sub result {
    my $self = shift;
    return $self->{out}->{R};
}

1;
__END__

=head1 NAME

Cipher::Stream::Trivium - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Cipher::Stream::Trivium;

  my $T = Cipher::Stream::Trivium->new('1' x 80,);

  my $stream;
  for (1..1000) {
      print $T->{A}->to_Bin."\n";
      print $T->{B}->to_Bin."\n";
      print $T->{C}->to_Bin."\n";
      $T->generate;
      $stream .= $T->result;
  }

  print "Cryptostream: $stream\n";

=head1 DESCRIPTION

=over 1

Trivium is a synchronous stream cipher designed to provide a flexible trade-off between speed and gate count in hardware, and reasonably efficient software implementation.

Trivium was submitted to the Profile II (hardware) of the eSTREAM competition by its authors, Christophe De Canniere and Bart Preneel, and has been selected as part of the portfolio for low area hardware ciphers (Profile 2) by the eSTREAM project. It is not patented and has been specified as an International Standard under ISO/IEC 29192-3.[1]

It generates up to 264 bits of output from an 80-bit key and an 80-bit IV. It is the simplest eSTREAM entrant; while it shows remarkable resistance to cryptanalysis for its simplicity and performance, recent attacks leave the security margin looking rather slim.

=back

=head1 SEE ALSO

L<https://en.wikipedia.org/wiki/Trivium_%28cipher%29>

=head1 AUTHOR

Ruben de Groot, ruben at hacktor.com

Git Repository: L<https://github.com/hacktor/Cipher-Stream-Trivium>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by ruben

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.24.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
