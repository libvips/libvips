create_sources = files(
    'perlin.c',
    'worley.c',
    'create.c',
    'gaussmat.c',
    'logmat.c',
    'buildlut.c',
    'invertlut.c',
    'tonelut.c',
    'identity.c',
    'point.c',
    'mask.c',
    'mask_ideal.c',
    'mask_ideal_ring.c',
    'mask_ideal_band.c',
    'mask_butterworth.c',
    'mask_butterworth_ring.c',
    'mask_butterworth_band.c',
    'mask_gaussian.c',
    'mask_gaussian_ring.c',
    'mask_gaussian_band.c',
    'mask_fractal.c',
    'fractsurf.c',
    'eye.c',
    'grey.c',
    'xyz.c',
    'black.c',
    'text.c',
    'gaussnoise.c',
    'sines.c',
    'zone.c',
)

create_headers = files(
    'pcreate.h',
    'point.h',
    'pmask.h',
)

create_lib = static_library('create',
    create_sources,
    create_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += create_lib
