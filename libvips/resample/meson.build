resample_sources = files(
    'thumbnail.c',
    'mapim.c',
    'affine.c',
    'quadratic.c',
    'resample.c',
    'similarity.c',
    'resize.c',
    'shrink.c',
    'shrinkh.c',
    'shrinkv.c',
    'reduce.c',
    'reduceh.cpp',
    'reducev.cpp',
    'interpolate.c',
    'transform.c',
    'bicubic.cpp',
    'lbb.cpp',
    'nohalo.cpp',
    'vsqbs.cpp',
)

resample_headers = files(
    'presample.h',
    'templates.h',
)

libvips_sources += resample_sources

resample_lib = static_library('resample',
    resample_sources,
    resample_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += resample_lib
