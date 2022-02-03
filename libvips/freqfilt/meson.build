freqfilt_sources = files(
    'freqfilt.c',
    'fwfft.c',
    'invfft.c',
    'freqmult.c',
    'spectrum.c',
    'phasecor.c',
)

freqfilt_headers = files(
    'pfreqfilt.h',
)

libvips_sources += freqfilt_sources

freqfilt_lib = static_library('freqfilt',
    freqfilt_sources,
    freqfilt_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += freqfilt_lib
