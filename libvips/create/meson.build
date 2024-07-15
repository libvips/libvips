create_sources = files(
    'black.c',
    'buildlut.c',
    'create.c',
    'eye.c',
    'fractsurf.c',
    'gaussmat.c',
    'gaussnoise.c',
    'grey.c',
    'identity.c',
    'invertlut.c',
    'logmat.c',
    'mask_butterworth_band.c',
    'mask_butterworth.c',
    'mask_butterworth_ring.c',
    'mask.c',
    'mask_fractal.c',
    'mask_gaussian_band.c',
    'mask_gaussian.c',
    'mask_gaussian_ring.c',
    'mask_ideal_band.c',
    'mask_ideal.c',
    'mask_ideal_ring.c',
    'perlin.c',
    'point.c',
    'sdf.c',
    'sines.c',
    'text.c',
    'tonelut.c',
    'worley.c',
    'xyz.c',
    'zone.c',
)

create_headers = files(
    'pcreate.h',
    'pmask.h',
    'point.h',
)

libvips_sources += create_sources

create_lib = static_library('create',
    create_sources,
    create_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += create_lib
