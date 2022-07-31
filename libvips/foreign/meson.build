if get_option('nsgif')
    subdir('libnsgif')
endif

foreign_sources = files(
    'analyze2vips.c',
    'analyzeload.c',
    'cairo.c',
    'cgifsave.c',
    'csvload.c',
    'csvsave.c',
    'dzsave.c',
    'exif.c',
    'fits.c',
    'fitsload.c',
    'fitssave.c',
    'foreign.c',
    'jp2kload.c',
    'jp2ksave.c',
    'jpeg2vips.c',
    'jpegload.c',
    'jpegsave.c',
    'magickload.c',
    'magicksave.c',
    'matlab.c',
    'matload.c',
    'matrixload.c',
    'matrixsave.c',
    'niftiload.c',
    'niftisave.c',
    'nsgifload.c',
    'openexr2vips.c',
    'openexrload.c',
    'pdfiumload.c',
    'pngload.c',
    'pngsave.c',
    'ppmload.c',
    'ppmsave.c',
    'quantise.c',
    'radiance.c',
    'radload.c',
    'radsave.c',
    'rawload.c',
    'rawsave.c',
    'spngload.c',
    'spngsave.c',
    'svgload.c',
    'tiff2vips.c',
    'tiff.c',
    'tiffload.c',
    'tiffsave.c',
    'vips2jpeg.c',
    'vips2tiff.c',
    'vips2webp.c',
    'vipsload.c',
    'vipspng.c',
    'vipssave.c',
    'webp2vips.c',
    'webpload.c',
    'webpsave.c',
)

foreign_headers = files(
    'dbh.h',
    'jpeg.h',
    'pforeign.h',
    'quantise.h',
    'tiff.h',
)

# We still need to include the GObject part of a loader/saver
# if it is not built as a dynamically loadable module.
magick_module_sources = files(
    'magick.c',
    'magick2vips.c',
    'magick6load.c',
    'magick7load.c',
    'vips2magick.c',
)

magick_module_headers = files(
    'magick.h',
)

if not magick_module
    foreign_sources += magick_module_sources
    foreign_headers += magick_module_headers
endif

jpeg_xl_module_sources = files(
    'jxlload.c',
    'jxlsave.c',
)

if not libjxl_module
    foreign_sources += jpeg_xl_module_sources
endif

heif_module_sources = files(
    'heifload.c',
    'heifsave.c',
)

if not libheif_module
    foreign_sources += heif_module_sources
endif

poppler_module_sources = files(
    'popplerload.c',
)

if not libpoppler_module
    foreign_sources += poppler_module_sources
endif

openslide_module_sources = files(
    'openslideload.c',
)

if not openslide_module
    foreign_sources += openslide_module_sources
endif

libvips_sources += foreign_sources

foreign_lib = static_library('foreign',
    foreign_sources,
    foreign_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += foreign_lib
