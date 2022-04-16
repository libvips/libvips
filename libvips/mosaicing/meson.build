mosaicing_sources = files(
    'mosaicing.c',
    'merge.c',
    'mosaic.c',
    'match.c',
    'mosaic1.c',
    'chkpair.c',
    'matrixinvert.c',
    'global_balance.c',
    'lrmerge.c',
    'tbmerge.c',
    'lrmosaic.c',
    'tbmosaic.c',
    'remosaic.c',
    'im_avgdxdy.c',
    'im_clinear.c',
    'im_improve.c',
    'im_initialize.c',
    'im_lrcalcon.c',
    'im_tbcalcon.c',
)

mosaicing_headers = files(
    'global_balance.h',
    'pmosaicing.h',
)

libvips_sources += mosaicing_sources

mosaicing_lib = static_library('mosaicing',
    mosaicing_sources,
    mosaicing_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += mosaicing_lib
