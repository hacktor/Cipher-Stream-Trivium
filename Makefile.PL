use 5.024001;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'Cipher::Stream::Trivium',
    VERSION_FROM      => 'lib/Cipher/Stream/Trivium.pm',
    PREREQ_PM         => {
                            Bit::Vector => 0,
                         },
    ABSTRACT_FROM     => 'lib/Cipher/Stream/Trivium.pm',
    AUTHOR            => 'Ruben de Groot <ruben at hacktor.com>',
    LICENSE           => 'perl',
);
