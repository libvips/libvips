convolution_sources = files(
    'canny.c',
    'sobel.c',
    'convolution.c',
    'correlation.c',
    'conv.c',
    'conva.c',
    'convf.c',
    'convi.c',
    'convasep.c',
    'convsep.c',
    'compass.c',
    'fastcor.c',
    'spcor.c',
    'sharpen.c',
    'gaussblur.c',
)

convolution_headers = files(
    'pconvolution.h',
    'correlation.h',
)

libvips_sources += convolution_sources


convolution_lib = static_library('convolution',
    convolution_sources,
    convolution_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += convolution_lib
