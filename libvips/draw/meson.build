draw_sources = files(
    'draw.c',
    'drawink.c',
    'draw_circle.c',
    'draw_flood.c',
    'draw_mask.c',
    'draw_image.c',
    'draw_rect.c',
    'draw_line.c',
    'draw_smudge.c',
)

draw_headers = files(
    'pdraw.h',
    'drawink.h',
)

libvips_sources += draw_sources

draw_lib = static_library('draw',
    draw_sources,
    draw_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += draw_lib
