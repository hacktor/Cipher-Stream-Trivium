package Cipher::Stream::Trivium;

use 5.024001;
use strict;
#use warnings;
use Bit::Vector;
use Carp;

our @ISA = qw();
our $VERSION = '0.1.1';

sub new {
    my $class = shift;
    my $self = {
        # shiftregister C, 111 bits with last 3 set
        C   => Bit::Vector->new_Dec(111,7),
        iv  => 0,  # Initialization Vector
        key => 0   # Key
    };
    while (my $arg = shift @_) {
        $self->{key} = shift @_ if $arg =~ /^key$/;
        $self->{iv} = shift @_ if $arg =~ /^iv$/;
    }

    # shiftregister A, 93 bits filled with 80 bit key
    if ($self->{key} !~ /^[01]{80}$/) {
      carp "Padding Key $self->{key} to 80 bits" if $self->{key} =~ /^[01]{1,80}$/;
      if ($self->{key} =~ /^[01]{81,}$/) {
        $self->{key} = substr $self->{key}, 0, 80;
        carp "Truncing Key to 80 bits: $self->{key}";
      } elsif (($self->{key} * 1) eq $self->{key}) {
        $self->{key} = sprintf "%080b", $self->{key};
        carp "Converting numeral key to 80 bits: $self->{key}";
      } else {
        croak "Invalid Key; should be 80n binary bits"
      }
    }
    $self->{A} = Bit::Vector->new_Bin(93, sprintf "%093s", $self->{key});

    # shiftregister B, 111 bits filled with 80 bit initialization vector
    if ($self->{iv} !~ /^[01]{1,80}$/) {
      if ($self->{iv} =~ /^[01]{81,}$/) {
        $self->{iv} = substr $self->{iv}, 0, 80;
        carp "Truncing IV to 80 bits: $self->{iv}";
      } elsif (($self->{iv} * 1) eq $self->{iv}) {
        $self->{iv} = sprintf "%080b", $self->{iv};
        carp "Converting numeral iv to 80 bits: $self->{iv}";
      } else {
        croak "Invalid IV; not a bitstring of <= 80 bits";
      }
    }
    $self->{B} = Bit::Vector->new_Bin(84, sprintf "%084s", $self->{iv});

    bless $self,$class;
}

sub _generate {
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

    ## shifting and adding generated bits to the left ##
    $self->{$_}->Move_Right(1) for 'A','B','C';
    $self->{$_}->MSB($self->{out}->{$_}) for 'A','B','C';
}

sub init {
    my $self = shift;
    my $steps = shift;
    $steps = 1152 unless $steps;
    $self->_generate for 1..$steps;
}

sub next {
    my $self = shift;
    my $steps = shift or 1;
    my $result;
    for (1..$steps) {
        $self->_generate;
        $result .= $self->{out}->{R};
    }
    return $result;
}

1;
__END__

=head1 NAME

Cipher::Stream::Trivium - Perl extension for Stream Cipher Trivium

=head1 SYNOPSIS

  use Cipher::Stream::Trivium;

  my $T = Cipher::Stream::Trivium->new(key => '0110' x 20, iv => 314156);

  $T->init();                    # initialize the stream with 1152 steps

  $T->init(10);                  # or some other value

  my $stream = $T->next(128);    # generate next 128 bits

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
