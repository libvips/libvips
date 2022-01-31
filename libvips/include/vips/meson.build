public_other_headers = files(
    'almostdeprecated.h',
    'buf.h',
    'connection.h',
    'dbuf.h',
    'debug.h',
    'deprecated.h',
    'dispatch.h',
    'format.h',
    'gate.h',
    'generate.h',
    'intl.h',
    'mask.h',
    'private.h',
    'sbuf.h',
    'semaphore.h',
    'thread.h',
    'threadpool.h',
    'transform.h',
    'util.h',
    'vector.h',
    'video.h',
    'vips7compat.h',
)

public_headers = files(
    'arithmetic.h',
    'basic.h',
    'colour.h',
    'conversion.h',
    'convolution.h',
    'create.h',
    'draw.h',
    'error.h',
    'foreign.h',
    'freqfilt.h',
    'header.h',
    'histogram.h',
    'image.h',
    'interpolate.h',
    'memory.h',
    'morphology.h',
    'mosaicing.h',
    'object.h',
    'operation.h',
    'rect.h',
    'region.h',
    'resample.h',
    'type.h',
    'vips.h',
)

enumtypes = gnome.mkenums(
    'enumtypes',
    sources: files(
        'resample.h',
        'memory.h',
        'create.h',
        'foreign.h',
        'arithmetic.h',
        'conversion.h',
        'util.h',
        'image.h',
        'colour.h',
        'operation.h',
        'convolution.h',
        'morphology.h',
        'draw.h',
        'basic.h',
        'object.h',
        'region.h'
    ),
    h_template: 'enumtypes.h.in',
    c_template: 'enumtypes.c.in',
    install_header: true,
    install_dir: get_option('prefix') / get_option('includedir') / 'vips'
)

vips_verbose_config = []
vips_verbose_config += 'enable debug: @0@'.format(get_option('debug'))
vips_verbose_config += 'enable deprecated library components: @0@'.format(get_option('deprecated'))
vips_verbose_config += 'enable modules: @0@'.format(modules_enabled)
vips_verbose_config += 'use fftw3 for FFT: @0@'.format(fftw_dep.found())
vips_verbose_config += 'accelerate loops with orc: @0@'.format(orc_dep.found())
vips_verbose_config += 'ICC profile support with lcms: @0@'.format(lcms_dep.found())
vips_verbose_config += 'zlib: @0@'.format(zlib_dep.found())
vips_verbose_config += 'text rendering with pangocairo: @0@'.format(pangocairo_dep.found())
vips_verbose_config += 'font file support with fontconfig: @0@'.format(fontconfig_dep.found())
vips_verbose_config += 'RAD load/save: @0@'.format(get_option('radiance'))
vips_verbose_config += 'Analyze7 load/save: @0@'.format(get_option('analyze'))
vips_verbose_config += 'PPM load/save: @0@'.format(get_option('ppm'))
vips_verbose_config += 'GIF load: @0@'.format(get_option('nsgif'))
vips_verbose_config += 'GIF save with cgif: @0@'.format(cgif_dep.found())
vips_verbose_config += 'EXIF metadata support with libexif: @0@'.format(libexif_dep.found())
vips_verbose_config += 'JPEG load/save with libjpeg: @0@'.format(libjpeg_dep.found())
vips_verbose_config += 'JXL load/save with libjxl: @0@ (dynamic module: @1@)'.format(libjxl_dep.found(), get_option('jpeg-xl-module'))
vips_verbose_config +='JPEG2000 load/save with libopenjp2: @0@'.format(libopenjp2_dep.found())
vips_verbose_config += 'PNG load with libspng: @0@'.format(spng_dep.found())
vips_verbose_config += 'PNG load/save with libpng: @0@'.format(png_dep.found())
vips_verbose_config += 'selected quantisation package: @0@'.format(quantisation_package.found() ? quantisation_package.name() : 'none')
vips_verbose_config += 'TIFF load/save with libtiff: @0@'.format(libtiff_dep.found())
vips_verbose_config += 'image pyramid save: @0@'.format(gsf_dep.found())
vips_verbose_config += 'HEIC/AVIF load/save with libheif: @0@ (dynamic module: @1@)'.format(libheif_dep.found(), get_option('heif-module'))
vips_verbose_config += 'WebP load/save with libwebp: @0@'.format(libwebp_dep.found())
vips_verbose_config += 'PDF load with PDFium: @0@'.format(pdfium_dep.found())
vips_verbose_config += 'PDF load with poppler-glib: @0@ (dynamic module: @1@)'.format(libpoppler_dep.found(), get_option('poppler-module'))
vips_verbose_config += 'SVG load with librsvg-2.0: @0@'.format(librsvg_dep.found())
vips_verbose_config += 'EXR load with OpenEXR: @0@'.format(openexr_dep.found())
vips_verbose_config += 'OpenSlide load: @0@ (dynamic module: @1@)'.format(openslide_dep.found(), get_option('openslide-module'))
vips_verbose_config += 'Matlab load with matio: @0@'.format(matio_dep.found())
vips_verbose_config += 'NIfTI load/save with niftiio: @0@'.format(libnifti_dep.found())
vips_verbose_config += 'FITS load/save with cfitsio: @0@'.format(cfitsio_dep.found())
vips_verbose_config += 'Magick package: @0@ (dynamic module: @1@)'.format(magick_dep.found(), get_option('magick-module'))
if magick_dep.found()
    magick_version_str = 'magick' + magick_dep.version().split('.')[0]
else
    magick_version_str = 'none'
endif
vips_verbose_config += 'Magick API version: @0@'.format(magick_version_str)
vips_verbose_config += 'load with libMagickCore: @0@'.format(magick_dep.found() and 'load' in get_option('magick-features'))
vips_verbose_config += 'save with libMagickCore: @0@'.format(magick_dep.found() and 'save' in get_option('magick-features'))

version_data = configuration_data()
version_data.set('VIPS_VERSION', meson.project_version())
version_data.set('VIPS_VERSION_STRING', meson.project_version())
version_data.set('VIPS_MAJOR_VERSION', version_major)
version_data.set('VIPS_MINOR_VERSION', version_minor)
version_data.set('VIPS_MICRO_VERSION', version_patch)
version_data.set('LIBRARY_CURRENT', library_current)
version_data.set('LIBRARY_REVISION', library_revision)
version_data.set('LIBRARY_AGE', library_age)
version_data.set('VIPS_CONFIG', ', '.join(vips_verbose_config))
#FIXME: Do not require this
if target_machine.system() == 'windows' or target_machine.system() == 'cygwin'
    version_data.set('VIPS_EXEEXT', '.exe')
else
    version_data.set('VIPS_EXEEXT', '')
endif
version_data.set10('VIPS_ENABLE_DEPRECATED', get_option('deprecated'))

version_header = configure_file(
    input: 'version.h.in',
    output: 'version.h',
    configuration: version_data,
    install: true,
    install_dir: get_option('prefix') / get_option('includedir') / 'vips'
)

#FIXME: Do not require this
soname_data = configuration_data()
if target_machine.system() == 'windows'
    soname_data.set_quoted('VIPS_SONAME', 'vips-@0@.dll'.format(library_current - library_age))
elif target_machine.system() == 'cygwin'
    soname_data.set_quoted('VIPS_SONAME', 'cygvips-@0@.dll'.format(library_current - library_age))
elif target_machine.system() == 'darwin'
    soname_data.set_quoted('VIPS_SONAME', 'libvips.dylib')
else
    soname_data.set_quoted('VIPS_SONAME', 'libvips.so')
endif
soname_header = configure_file(
    output: 'soname.h',
    configuration: soname_data,
    install: true,
    install_dir: get_option('prefix') / get_option('includedir') / 'vips'
)

libvips_sources += public_headers
libvips_sources += enumtypes
libvips_sources += version_header
libvips_sources += soname_header

install_headers(
    public_other_headers,
    public_headers,
    subdir: 'vips'
)

libvips_includedir = include_directories('..')
libvips_headers_dep = declare_dependency(
    sources: [
        public_headers,
        enumtypes[1],
        version_header,
        soname_header
    ],
    include_directories: libvips_includedir
)

libvips_deps += libvips_headers_dep
