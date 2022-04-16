histogram_sources = files(
    'histogram.c',
    'maplut.c',
    'case.c',
    'hist_unary.c',
    'hist_cum.c',
    'hist_norm.c',
    'hist_equal.c',
    'hist_plot.c',
    'hist_match.c',
    'hist_local.c',
    'percent.c',
    'hist_ismonotonic.c',
    'hist_entropy.c',
    'stdif.c',
)

histogram_headers = files(
    'phistogram.h',
    'hist_unary.h',
)

libvips_sources += histogram_sources

histogram_lib = static_library('histogram',
    histogram_sources,
    histogram_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += histogram_lib
