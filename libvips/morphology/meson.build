morphology_sources = files(
    'nearest.c',
    'morphology.c',
    'countlines.c',
    'rank.c',
    'morph.c',
    'labelregions.c',
)

morphology_headers = files(
    'pmorphology.h',
)

libvips_sources += morphology_sources

morphology_lib = static_library('morphology',
    morphology_sources,
    morphology_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += morphology_lib
