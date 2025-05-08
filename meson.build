project('vips', 'c', 'cpp',
    version: '8.17.0',
    meson_version: '>=0.55',
    default_options: [
        # this is what glib uses (one of our required deps), so we use it too
        'c_std=gnu99',
        # we use some C++11 features
        'cpp_std=c++11',
        # do a release (optimised) build by default
        'buildtype=release',
        # turn off asserts etc. in release mode
        'b_ndebug=if-release'
    ]
)

version_parts = meson.project_version().split('.')
version_major = version_parts[0]
version_minor = version_parts[1]
version_patch = version_parts[2]

# rules:
# sources changed: increment revision
# binary interface changed: increment current, reset revision to 0
#   binary interface changes backwards compatible?: increment age
#   binary interface changes not backwards compatible?: reset age to 0
library_revision = 0
library_current = 61
library_age = 19
library_version = '@0@.@1@.@2@'.format(library_current - library_age, library_age, library_revision)
darwin_versions = [library_current + 1, '@0@.@1@'.format(library_current + 1, library_revision)]

gnome = import('gnome')
pymod = import('python')
pkg = import('pkgconfig')
i18n = import('i18n')

# if we're optimising (eg. release mode) we turn off cast checks and g_asserts
if get_option('optimization') not in ['0', 'g']
    add_project_arguments('-DG_DISABLE_CAST_CHECKS', language: ['cpp', 'c'])
    add_project_arguments('-DG_DISABLE_CHECKS', language: ['cpp', 'c'])
    add_project_arguments('-DG_DISABLE_ASSERT', language: ['cpp', 'c'])
endif

# in debug mode we automatically enable leak checks
# also true for 'debugoptimized'
if get_option('debug')
    add_project_arguments('-DDEBUG_LEAK', language: ['cpp', 'c'])
endif

host_os = host_machine.system()
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

# Prevent use of void* pointer arithmetic to support MSVC
add_project_arguments(cc.get_supported_arguments('-Werror=pointer-arith'), language: ['cpp', 'c'])

# libFuzzer related things
fuzzing_engine = get_option('fuzzing_engine')
if fuzzing_engine == 'libfuzzer'
    if not cc.has_argument('-fsanitize=fuzzer')
        error('fuzzing_engine libfuzzer requires "-fsanitize=fuzzer"')
    endif
    fuzzer_args = ['-fsanitize=fuzzer-no-link', '-fsanitize=fuzzer']
    add_project_arguments(cc.first_supported_argument(fuzzer_args), language: ['cpp', 'c'])
endif

glib_dep = dependency('glib-2.0', version: '>=2.52')
gio_dep = dependency('gio-2.0')
gobject_dep = dependency('gobject-2.0')
gmodule_dep = dependency('gmodule-no-export-2.0', required: get_option('modules'))
expat_dep = dependency('expat')
thread_dep = dependency('threads')
m_dep = cc.find_library('m', required: false)

# Start to form our dependencies

# External dependencies we've detected
external_deps = [
    glib_dep,
    gio_dep,
    gobject_dep,
    gmodule_dep,
    expat_dep,
]

# External dependencies of modules we've detected
# These dependencies are not included in vips.pc
module_deps = []

# Required deps that may or may not be external versioned libraries
other_deps = [
    thread_dep,
    m_dep,
]

nodelete_link_args = cc.get_supported_link_arguments('-Wl,-z,nodelete')

prefix_dir = get_option('prefix')
lib_dir = prefix_dir / get_option('libdir')

project_source_root = meson.current_source_dir()
project_build_root = meson.current_build_dir()

if gmodule_dep.found() and gmodule_dep.get_variable(pkgconfig: 'gmodule_supported') == 'true'
    # Disable modules by default when building static libraries
    modules_enabled = get_option('modules').enabled() or get_option('default_library') == 'shared'
elif get_option('modules').enabled()
    error('GModule is not supported on your system, please reconfigure with -Dmodules=disabled')
else
    modules_enabled = false
endif

module_dir = lib_dir / 'vips-modules-@0@.@1@'.format(version_major, version_minor)

cfg_var = configuration_data()
cfg_var.set_quoted('G_LOG_DOMAIN', 'VIPS')

cfg_var.set('ENABLE_MODULES', modules_enabled)

# Detect and set symbol visibility
if get_option('default_library') == 'shared' and host_os in ['windows', 'cygwin']
    cfg_var.set('DLL_EXPORT', true)
    if cc.has_function_attribute('visibility:hidden')
        cfg_var.set('_VIPS_PUBLIC', '__attribute__((visibility("default"))) __declspec(dllexport)')
    else
        cfg_var.set('_VIPS_PUBLIC', '__declspec(dllexport)')
    endif
elif cc.has_function_attribute('visibility:hidden')
    cfg_var.set('_VIPS_PUBLIC', '__attribute__((visibility("default")))')
endif

# we also need to be able to mix vector and scalar arithmetic
vector_arithmetic_check = '''
typedef float v4f __attribute__((vector_size(4 * sizeof(float)),aligned(16)));
int main(void) {
    v4f f = {1, 2, 3, 4}; f *= 12.0;
    v4f g = {5, 6, 7, 8}; f = g > 0 ? g : -1 * g;
}
'''

# gcc 7.2 seems to work, but then gets confused by signed constants in templates
signed_constants_check = '''
typedef float v4f __attribute__((vector_size(4 * sizeof(float)),aligned(16)));
template <typename T>
static void
h( v4f B )
{
    v4f f;
    f = -1 * B;
}
'''

have_vector_artih = cpp.compiles(vector_arithmetic_check, name: 'Has vector arithmetic', dependencies: m_dep) and \
                    cpp.compiles(signed_constants_check, name: 'Has signed constants in vector templates', dependencies: m_dep)
cfg_var.set('HAVE_VECTOR_ARITH', have_vector_artih)

# HAVE_TARGET_CLONES
target_clones_check = '''
static int __attribute__((target_clones("default,avx")))
has_target_clones(void) {
    return 0;
}

int main(void) {
    int (*func)(void) = has_target_clones;
    return func();
}
'''
if meson.can_run_host_binaries()
    rres = cc.run(target_clones_check, args: '-Werror', name: 'Has target_clones attribute')
    have_target_clones = rres.compiled() and rres.returncode() == 0
else
    have_target_clones = cc.links(target_clones_check, args: '-Werror', name: 'Has target_clones attribute')
endif
cfg_var.set('HAVE_TARGET_CLONES', have_target_clones)

func_names = [ '_aligned_malloc', 'posix_memalign', 'memalign' ]
foreach func_name : func_names
    cfg_var.set('HAVE_' + func_name.to_upper(), cc.has_function(func_name))
endforeach

cfg_var.set('HAVE_PTHREAD_DEFAULT_NP', cc.has_function('pthread_setattr_default_np', args: '-D_GNU_SOURCE', prefix: '#include <pthread.h>', dependencies: thread_dep))

# needed by rsvg and others
zlib_dep = dependency('zlib', version: '>=0.4', required: get_option('zlib'))
if zlib_dep.found()
    external_deps += zlib_dep
    cfg_var.set('HAVE_ZLIB', true)
endif

libarchive_dep = dependency('libarchive', version: '>=3.0.0', required: get_option('archive'))
if libarchive_dep.found()
    external_deps += libarchive_dep
    cfg_var.set('HAVE_LIBARCHIVE', true)
endif

fftw_dep = dependency('fftw3', required: get_option('fftw'))
if fftw_dep.found()
    external_deps += fftw_dep
    cfg_var.set('HAVE_FFTW', true)
endif

# TODO: simplify this when requiring meson>=0.60.0
magick_dep = dependency(get_option('magick-package'), required: false)
if not magick_dep.found()
    # very old versions called it "ImageMagick"
    magick_dep = dependency('ImageMagick', required: get_option('magick'))
endif
magick_found = not get_option('magick').disabled() and magick_dep.found()
magick_module = false
if magick_found
    magick_module = modules_enabled and not get_option('magick-module').disabled()
    if magick_module
        cfg_var.set('MAGICK_MODULE', true)
        module_deps += magick_dep
    else
        external_deps += magick_dep
    endif
    magick7 = magick_dep.version().version_compare('>=7.0')
    # IM7 uses <MagickCore/MagickCore.h>
    # IM6 uses <magick/MagickCore.h> (since 6.2.3) but still provides <magick/api.h>
    # GM uses <magick/api.h>
    magick_include = magick7 ? '#include <MagickCore/MagickCore.h>' : '#include <magick/api.h>'
    if magick7
        cfg_var.set('HAVE_MAGICK7', true)
    else
        # come here for imagemagick6, and graphicsmagick1.x, which also uses
        # the im6 API
        cfg_var.set('HAVE_MAGICK6', true)
        cfg_var.set('HAVE_NUMBER_SCENES', cc.has_member('struct _ImageInfo', 'number_scenes', prefix: magick_include, dependencies: magick_dep))
        func_names = [ 'InheritException', 'AcquireExceptionInfo', 'SetImageProperty', 'SetImageExtent', 'AcquireImage', 'GetVirtualPixels', 'ResetImageProfileIterator', 'ResetImageAttributeIterator', 'ResetImagePropertyIterator', 'MagickCoreGenesis', 'SetImageOption', 'BlobToStringInfo', 'OptimizePlusImageLayers', 'OptimizeImageTransparency', 'GetMagicInfo' ]
        foreach func_name : func_names
            cfg_var.set('HAVE_' + func_name.to_upper(), cc.has_function(func_name, prefix: magick_include, dependencies: magick_dep))
        endforeach
        cfg_var.set('HAVE_CMYCOLORSPACE', cc.compiles(magick_include + '\nColorspaceType colorspace = CMYColorspace;', name: 'Has CMYColorspace', dependencies: magick_dep))
        cfg_var.set('HAVE_HCLPCOLORSPACE', cc.compiles(magick_include + '\nColorspaceType colorspace = HCLpColorspace;', name: 'Has HCLpColorspace', dependencies: magick_dep))
        # GetImageMagick() takes two args under GM, three under IM
        cfg_var.set('HAVE_GETIMAGEMAGICK3', cc.compiles(magick_include + '\nint main() {(void)GetImageMagick(NULL, 0, NULL);}', name: 'GetImageMagick takes three arguments', dependencies: magick_dep))
    endif

    magick_features = [ 'load', 'save' ]
    foreach feature : magick_features
        cfg_var.set('ENABLE_MAGICK' + feature.to_upper(), feature in get_option('magick-features'))
    endforeach

    if 'save' in get_option('magick-features')
        cfg_var.set('HAVE_IMPORTIMAGEPIXELS', cc.has_function('ImportImagePixels', prefix: magick_include, dependencies: magick_dep))
        cfg_var.set('HAVE_IMAGESTOBLOB', cc.has_function('ImagesToBlob', prefix: magick_include, dependencies: magick_dep))
    endif
endif

cfitsio_dep = dependency('cfitsio', required: get_option('cfitsio'))
if cfitsio_dep.found()
    external_deps += cfitsio_dep
    cfg_var.set('HAVE_CFITSIO', true)
endif

# quant package we use
quantisation_package = disabler()

imagequant_dep = dependency('imagequant', required: get_option('imagequant'))
if imagequant_dep.found()
    external_deps += imagequant_dep
    cfg_var.set('HAVE_IMAGEQUANT', true)
    quantisation_package = imagequant_dep
endif

# only if libimagequant not found
quantizr_dep = disabler()
if not quantisation_package.found()
    quantizr_dep = dependency('quantizr', required: get_option('quantizr'))
    if quantizr_dep.found()
        external_deps += quantizr_dep
        cfg_var.set('HAVE_QUANTIZR', true)
        quantisation_package = quantizr_dep
    endif
endif

cgif_dep = disabler()
if quantisation_package.found()
    cgif_dep = dependency('cgif', version: '>=0.2.0', required: get_option('cgif'))
    if cgif_dep.found()
        external_deps += cgif_dep
        cfg_var.set('HAVE_CGIF', true)
        cfg_var.set('HAVE_CGIF_ATTR_NO_LOOP', cc.get_define('CGIF_ATTR_NO_LOOP', prefix: '#include <cgif.h>', dependencies: cgif_dep) != '')
        cfg_var.set('HAVE_CGIF_FRAME_ATTR_INTERLACED', cc.get_define('CGIF_FRAME_ATTR_INTERLACED', prefix: '#include <cgif.h>', dependencies: cgif_dep) != '')
        cfg_var.set('HAVE_CGIF_GEN_KEEP_IDENT_FRAMES', cc.get_define('CGIF_GEN_KEEP_IDENT_FRAMES', prefix: '#include <cgif.h>', dependencies: cgif_dep) != '')
    endif
endif

libexif_dep = dependency('libexif', version: '>=0.6', required: get_option('exif'))
if libexif_dep.found()
    external_deps += libexif_dep
    cfg_var.set('HAVE_EXIF', true)
    # some libexif packages need include <libexif/poop.h>, some just <poop.h>
    # how annoying
    # libexif includes don't need libexif prefix
    cfg_var.set('UNTAGGED_EXIF', cc.has_header('exif-data.h', dependencies: libexif_dep))
    # 0.6.22 adds a couple of EXIF 2.3 ASCII tags
    cfg_var.set('HAVE_EXIF_0_6_22', libexif_dep.version().version_compare('>=0.6.22'))
    # 0.6.23 adds some OffsetTime* and GPS* ASCII tags
    cfg_var.set('HAVE_EXIF_0_6_23', libexif_dep.version().version_compare('>=0.6.23'))
endif

libjpeg_dep = dependency('libjpeg', required: get_option('jpeg'))
if libjpeg_dep.found()
    external_deps += libjpeg_dep
    cfg_var.set('HAVE_JPEG', true)
    # features like trellis quant are exposed as extension parameters ...
    # mozjpeg 3.2 and later have #define JPEG_C_PARAM_SUPPORTED, but we must
    # work with earlier versions
    cfg_var.set('HAVE_JPEG_EXT_PARAMS', cc.has_function('jpeg_c_bool_param_supported', prefix: '#include <stdio.h>\n#include <jpeglib.h>', dependencies: libjpeg_dep))
endif

# png package we use
png_package = disabler()

# Look for libspng first
# - it's sometimes called "spng.pc", sometimes "libspng.pc", we must search for
#   both
# - we need 0.7+ for PNG write support
# TODO: simplify this when requiring meson>=0.60.0
spng_dep = dependency('spng', version: '>=0.7', required: false)
if not spng_dep.found()
    spng_dep = dependency('libspng', version: '>=0.7', required: get_option('spng'))
endif
if not get_option('spng').disabled() and spng_dep.found()
    external_deps += spng_dep
    cfg_var.set('HAVE_SPNG', true)
    png_package = spng_dep
endif

# only if libspng not found
if not png_package.found()
    png_dep = dependency('libpng', version: '>=1.2.9', required: get_option('png'))
    if png_dep.found()
        external_deps += png_dep
        cfg_var.set('HAVE_PNG', true)
        cfg_var.set('HAVE_PNG_SET_CHUNK_MALLOC_MAX', cc.has_function('png_set_chunk_malloc_max', prefix: '#include <png.h>', dependencies: png_dep))
        png_package = png_dep
    endif
endif

# libwebp ... target 0.6+ to reduce complication
# webp has the stuff for handling metadata in two separate libraries -- we
# insist on having both of them
libwebp_dep = dependency('libwebp', version: '>=0.6', required: get_option('webp'))
if libwebp_dep.found()
    external_deps += libwebp_dep
    external_deps += dependency('libwebpmux', version: '>=0.6')
    external_deps += dependency('libwebpdemux', version: '>=0.6')
    cfg_var.set('HAVE_LIBWEBP', true)
endif

pangocairo_dep = dependency('pangocairo', version: '>=1.32.6', required: get_option('pangocairo'))
if pangocairo_dep.found()
    external_deps += pangocairo_dep
    cfg_var.set('HAVE_PANGOCAIRO', true)
endif

# text rendering with fontconfig requires pangoft2
pangoft2_dep = dependency('pangoft2', version: '>=1.32.6', required: get_option('fontconfig'))
fontconfig_dep = dependency('fontconfig', required: get_option('fontconfig'))
fontconfig_found = pangoft2_dep.found() and fontconfig_dep.found() and pangocairo_dep.found()
if fontconfig_found
    external_deps += pangoft2_dep
    external_deps += fontconfig_dep
    cfg_var.set('HAVE_FONTCONFIG', true)
endif

libtiff_dep = dependency('libtiff-4', required: get_option('tiff'))
if libtiff_dep.found()
    external_deps += libtiff_dep
    cfg_var.set('HAVE_TIFF', true)
    # ZSTD and WEBP in TIFF added in libtiff 4.0.10
    cfg_var.set('HAVE_TIFF_COMPRESSION_WEBP', cc.get_define('COMPRESSION_WEBP', prefix: '#include <tiff.h>', dependencies: libtiff_dep) != '')
    # TIFFOpenOptions added in libtiff 4.5.0
    cfg_var.set('HAVE_TIFF_OPEN_OPTIONS', cc.has_function('TIFFOpenOptionsAlloc', prefix: '#include <tiffio.h>', dependencies: libtiff_dep))
    # TIFFOpenOptionsSetMaxCumulatedMemAlloc added in libtiff 4.7.0
    cfg_var.set('HAVE_TIFF_OPEN_OPTIONS_SET_MAX_CUMULATED_MEM_ALLOC', cc.has_function('TIFFOpenOptionsSetMaxCumulatedMemAlloc', prefix: '#include <tiffio.h>', dependencies: libtiff_dep))
endif

# 2.40.3 so we get the UNLIMITED open flag
librsvg_dep = dependency('librsvg-2.0', version: '>=2.40.3', required: get_option('rsvg'))
cairo_dep = dependency('cairo', version: '>=1.2', required: get_option('rsvg'))
librsvg_found = librsvg_dep.found() and cairo_dep.found()
if librsvg_found
    external_deps += librsvg_dep
    external_deps += cairo_dep
    cfg_var.set('HAVE_RSVG', true)
    # rsvg_handle_set_stylesheet added in librsvg 2.48.0
    cfg_var.set('HAVE_RSVG_HANDLE_SET_STYLESHEET', cc.has_function('rsvg_handle_set_stylesheet', dependencies: librsvg_dep))
endif

openslide_dep = dependency('openslide', version: '>=3.4.0', required: get_option('openslide'))
openslide_module = false
if openslide_dep.found()
    openslide_module = modules_enabled and not get_option('openslide-module').disabled()
    if openslide_module
        cfg_var.set('OPENSLIDE_MODULE', true)
        module_deps += openslide_dep
    else
        external_deps += openslide_dep
    endif
    cfg_var.set('HAVE_OPENSLIDE', true)
    cfg_var.set('HAVE_OPENSLIDE_ICC', cc.has_function('openslide_get_icc_profile_size', dependencies: openslide_dep))
    cfg_var.set('HAVE_OPENSLIDE_CACHE_CREATE', cc.has_function('openslide_cache_create', dependencies: openslide_dep))
endif

matio_dep = dependency('matio', required: get_option('matio'))
if matio_dep.found()
    external_deps += matio_dep
    cfg_var.set('HAVE_MATIO', true)
endif

# lcms ... refuse to use lcms1
lcms_dep = dependency('lcms2', required: get_option('lcms'))
if lcms_dep.found()
    external_deps += lcms_dep
    cfg_var.set('HAVE_LCMS2', true)
endif

# require 1.2.2 since 1.2.1 has a broken ImfCloseTiledInputFile()
openexr_dep = dependency('OpenEXR', version: '>=1.2.2', required: get_option('openexr'))
if openexr_dep.found()
    external_deps += openexr_dep
    cfg_var.set('HAVE_OPENEXR', true)
endif

# 2.4 is the first one to have working threading and tiling
libopenjp2_dep = dependency('libopenjp2', version: '>=2.4', required: get_option('openjpeg'))
if libopenjp2_dep.found()
    external_deps += libopenjp2_dep
    cfg_var.set('HAVE_LIBOPENJP2', true)
endif

# simd package we use
simd_package = disabler()

# Require 1.0.5 to support the `ReorderDemote2To(u8, i16, i16)` operation
# See: https://github.com/google/highway/pull/1247
libhwy_dep = dependency('libhwy', version: '>=1.0.5', required: get_option('highway'))
if libhwy_dep.found()
    external_deps += libhwy_dep
    cfg_var.set('HAVE_HWY', true)
    # 1.1.0 adds `InterleaveWhole{Lower,Upper}` and `Dup128VecFromValues`
    cfg_var.set('HAVE_HWY_1_1_0', libhwy_dep.version().version_compare('>=1.1.0'))
    # Always disable SSSE3 since it is rare to have SSSE3 but not SSE4
    disabled_targets = ['HWY_SSSE3']
    # Optionally, build without AVX512 support (helps to reduce binary size at the cost of performance)
    #disabled_targets += ['HWY_AVX3']
    #disabled_targets += ['HWY_AVX3_ZEN4']
    #disabled_targets += ['HWY_AVX3_SPR']
    add_project_arguments('-DHWY_DISABLED_TARGETS=@0@'.format('|'.join(disabled_targets)), language: ['cpp'])
    simd_package = libhwy_dep
endif

# only if highway not found
if not simd_package.found()
    # we use loadpw etc.
    orc_dep = dependency('orc-0.4', version: '>=0.4.11', required: get_option('orc'))
    if orc_dep.found()
        external_deps += orc_dep
        cfg_var.set('HAVE_ORC', true)
        # orc 0.4.30+ works with cf-protection, but 0.4.30 has a bug with multiple
        # definitions of OrcTargetPowerPCFlags, so insist on 0.4.31
        cfg_var.set('HAVE_ORC_CF_PROTECTION', orc_dep.version().version_compare('>=0.4.31'))
        simd_package = orc_dep
    endif
endif

# pdf loader we use
pdf_loader = disabler()

# pick 4200 as the starting version number ... no reason, really, it'd
# probably work with much older versions
pdfium_dep = dependency('pdfium', version: '>=4200', required: get_option('pdfium'))
if pdfium_dep.found()
    external_deps += pdfium_dep
    cfg_var.set('HAVE_PDFIUM', true)
    pdf_loader = pdfium_dep
endif

libheif_dep = dependency('libheif', version: '>=1.4.0', required: get_option('heif'))
libheif_module = false
if libheif_dep.found()
    libheif_module = modules_enabled and not get_option('heif-module').disabled()
    if libheif_module
        cfg_var.set('HEIF_MODULE', true)
        module_deps += libheif_dep
    else
        external_deps += libheif_dep
    endif
    cfg_var.set('HAVE_HEIF', true)
    # added in 1.6.0
    cfg_var.set('HAVE_HEIF_COLOR_PROFILE', cpp.has_function('heif_image_handle_get_raw_color_profile', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
    cfg_var.set('HAVE_HEIF_SET_MAX_IMAGE_SIZE_LIMIT', cpp.has_function('heif_context_set_maximum_image_size_limit', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
    # added in 1.7.0
    cfg_var.set('HAVE_HEIF_DECODING_OPTIONS_CONVERT_HDR_TO_8BIT', cpp.has_member('struct heif_decoding_options', 'convert_hdr_to_8bit', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
    # heif_main_brand added in 1.4.0, but heif_avif appeared in 1.7 ... just check
    # the libheif version number since testing for enums is annoying
    cfg_var.set('HAVE_HEIF_AVIF', libheif_dep.version().version_compare('>=1.7.0'))
    # added in 1.10.0
    cfg_var.set('HAVE_HEIF_ENCODER_PARAMETER_GET_VALID_INTEGER_VALUES', cpp.has_function('heif_encoder_parameter_get_valid_integer_values', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
    # added in 1.11.0
    cfg_var.set('HAVE_HEIF_ENCODING_OPTIONS_OUTPUT_NCLX_PROFILE', cpp.has_member('struct heif_encoding_options', 'output_nclx_profile', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
    # heif_init added in 1.13.0
    cfg_var.set('HAVE_HEIF_INIT', libheif_dep.version().version_compare('>=1.13.0'))
    # heif_encoding_options.image_orientation added in 1.14.0
    cfg_var.set('HAVE_HEIF_ENCODING_OPTIONS_IMAGE_ORIENTATION', cpp.has_member('struct heif_encoding_options', 'image_orientation', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
    # heif_error_success added in 1.17.0
    cfg_var.set('HAVE_HEIF_ERROR_SUCCESS', libheif_dep.version().version_compare('>=1.17.0'))
    # heif_get_disabled_security_limits added in 1.19.0
    cfg_var.set('HAVE_HEIF_GET_DISABLED_SECURITY_LIMITS', cpp.has_function('heif_get_disabled_security_limits', prefix: '#include <libheif/heif.h>', dependencies: libheif_dep))
endif

# need v0.11+ for chunked write
libjxl_dep = dependency('libjxl', version: '>=0.11', required: get_option('jpeg-xl'))
libjxl_threads_dep = dependency('libjxl_threads', version: '>=0.11', required: get_option('jpeg-xl'))
libjxl_found = libjxl_dep.found() and libjxl_threads_dep.found()
libjxl_module = false
if libjxl_found
    libjxl_module = modules_enabled and not get_option('jpeg-xl-module').disabled()
    if libjxl_module
        cfg_var.set('LIBJXL_MODULE', true)
        module_deps += libjxl_dep
        module_deps += libjxl_threads_dep
    else
        external_deps += libjxl_dep
        external_deps += libjxl_threads_dep
    endif
    cfg_var.set('HAVE_LIBJXL', true)
endif

# only if pdfium not found
libpoppler_module = false
if not pdf_loader.found()
    libpoppler_dep = dependency('poppler-glib', version: '>=0.16.0', required: get_option('poppler'))
    if not cairo_dep.found()
        cairo_dep = dependency('cairo', version: '>=1.2', required: get_option('poppler'))
    endif
    if libpoppler_dep.found() and cairo_dep.found()
        libpoppler_module = modules_enabled and not get_option('poppler-module').disabled()
        if libpoppler_module
            cfg_var.set('POPPLER_MODULE', true)
            module_deps += libpoppler_dep
            module_deps += cairo_dep
        else
            external_deps += libpoppler_dep
            external_deps += cairo_dep
        endif
        cfg_var.set('HAVE_POPPLER', true)
        pdf_loader = libpoppler_dep
    endif
endif

# niftiio.pc is not present, and only provides the CMake package definition
# files since v3.0.0, so, as a last resort, fall back on heuristic grabbing the
# libs when -Dnifti-prefix-dir=<PREFIX> is specified
#
# cmake find fails on ubuntu due to /usr/lib/x86_64-linux-gnu madness, so it's
# simplest to create a niftiio.pc in this case
#
# create /usr/lib/x86_64-linux-gnu/pkgconfig/niftiio.pc:
#
#   prefix=/usr
#   libdir=${prefix}/lib/x86_64-linux-gnu
#   includedir=${prefix}/include/nifti
#   Name: niftiio
#   Description: Core i/o routines for reading and writing nifti-1 format files
#   Version: 3.0.1
#   Requires: xproto
#   Libs: -L${libdir} -lniftiio -lznz
#   Cflags: -I${includedir}
#
# TODO: simplify this when requiring meson>=0.60.0
nifti_prefix_dir = get_option('nifti-prefix-dir')
libnifti_dep = dependency('niftiio', method: 'pkg-config', required: false)
if not libnifti_dep.found()
    libnifti_dep = dependency('NIFTI',
      version: '>=3.0.0',
      method: 'cmake',
      modules: ['NIFTI::niftiio'],
      required: get_option('nifti').enabled() and nifti_prefix_dir == '')
endif
if nifti_prefix_dir != '' and not libnifti_dep.found()
    nifti_inc = include_directories(nifti_prefix_dir / 'include' / 'nifti')
    nifti_lib = cc.find_library('niftiio', has_headers: ['nifti1_io.h'], header_include_directories: nifti_inc, required: get_option('nifti'))
    znz_lib = cc.find_library('znz', has_headers: ['znzlib.h'], header_include_directories: nifti_inc, required: get_option('nifti'))
    libnifti_dep = declare_dependency(dependencies: [nifti_lib, znz_lib], include_directories: nifti_inc)
endif
libnifti_found = not get_option('nifti').disabled() and libnifti_dep.found()
if libnifti_found
    external_deps += libnifti_dep
    cfg_var.set('HAVE_NIFTI', true)
endif

headers = [ 'sys/file.h', 'sys/param.h', 'sys/mman.h', 'unistd.h', 'io.h', 'direct.h' ]
foreach name : headers
    cfg_var.set('HAVE_' + name.underscorify().to_upper(), cc.has_header(name))
endforeach

cfg_var.set('ENABLE_DEPRECATED', get_option('deprecated'))
cfg_var.set('HAVE_NSGIF', get_option('nsgif'))
cfg_var.set('HAVE_PPM', get_option('ppm'))
cfg_var.set('HAVE_ANALYZE', get_option('analyze'))
cfg_var.set('HAVE_RADIANCE', get_option('radiance'))

gettext_domain = 'vips@0@.@1@'.format(version_major, version_minor)
cfg_var.set_quoted('GETTEXT_PACKAGE', gettext_domain)
cfg_var.set_quoted('VIPS_PREFIX', prefix_dir)
cfg_var.set_quoted('VIPS_LIBDIR', lib_dir)
if cc.has_function('ngettext')
    cfg_var.set('ENABLE_NLS', true)
    have_bind_textdomain_codeset = cc.has_function('bind_textdomain_codeset')
else
    libintl_dep = cc.find_library('intl', required: false)
    if libintl_dep.found()
        other_deps += libintl_dep
        cfg_var.set('ENABLE_NLS', true)
        have_bind_textdomain_codeset = cc.has_function('bind_textdomain_codeset', prefix: '#include <libintl.h>', dependencies: libintl_dep)
    else
        have_bind_textdomain_codeset = false
    endif
endif
cfg_var.set('HAVE_BIND_TEXTDOMAIN_CODESET', have_bind_textdomain_codeset)

if host_os == 'darwin'
    profile_dir = '/Library/ColorSync/Profiles'
elif host_os == 'windows'
    # need double escapes since this will get pasted into a #define in a C
    # header ... the C:\Windows is usually overwritten with the result of
    # GetWindowsDirectoryW()
    profile_dir = 'C:\\\\Windows\\\\System32\\\\spool\\\\drivers\\\\color'
else
    profile_dir = get_option('prefix') / get_option('datadir') / 'color' / 'icc'
endif
cfg_var.set_quoted('VIPS_ICC_DIR', profile_dir)

config_file = configure_file(
    configuration: cfg_var,
    output: 'config.h'
)

config_dep = declare_dependency(
    sources: config_file,
    include_directories: include_directories('.'),
    compile_args: '-DHAVE_CONFIG_H',
)

libvips_deps = [config_dep] + external_deps + other_deps

gir = find_program('g-ir-scanner', required: get_option('introspection'))
enable_introspection = gir.found() and (not meson.is_cross_build() or get_option('introspection').enabled())

build_summary = {
  'Build options':
    {'enable debug': [get_option('debug')],
     'enable deprecated': [get_option('deprecated')],
     'enable modules': [modules_enabled],
     'enable docs': [get_option('docs')],
     'enable C++ docs': [get_option('cpp-docs')],
     'enable introspection': [enable_introspection],
     'enable examples': [get_option('examples')],
     'enable C++ binding': [get_option('cplusplus')],
     'enable RAD load/save': [get_option('radiance')],
     'enable Analyze7 load': [get_option('analyze')],
     'enable PPM load/save': [get_option('ppm')],
     'enable GIF load': [get_option('nsgif')],
    },
}
build_features = {
  'Optional external packages':
    {'FFTs': ['fftw', fftw_dep],
     'SIMD support': ['libhwy or liborc', simd_package],
     'ICC profile support': ['lcms2', lcms_dep],
     'deflate compression': ['zlib', zlib_dep],
     'text rendering': ['pangocairo', pangocairo_dep],
     'font file support': ['fontconfig', fontconfig_found ? fontconfig_dep : disabler()],
     'EXIF metadata support': ['libexif', libexif_dep],
    },
  'External image format libraries':
    {'JPEG load/save': ['libjpeg', libjpeg_dep],
     'JXL load/save': ['libjxl', libjxl_found ? libjxl_dep : disabler(), libjxl_module],
     'JPEG2000 load/save': ['OpenJPEG', libopenjp2_dep],
     'PNG load/save': ['libspng or libpng', png_package],
     'image quantisation': ['imagequant or quantizr', quantisation_package],
     'TIFF load/save': ['libtiff', libtiff_dep],
     'image pyramid save': ['libarchive', libarchive_dep],
     'HEIC/AVIF load/save': ['libheif', libheif_dep, libheif_module],
     'WebP load/save': ['libwebp', libwebp_dep],
     'PDF load': ['PDFium or Poppler', pdf_loader, libpoppler_module],
     'SVG load': ['librsvg', librsvg_found ? librsvg_dep : disabler()],
     'EXR load': ['OpenEXR', openexr_dep],
     'WSI load': ['OpenSlide', openslide_dep, openslide_module],
     'Matlab load': ['Matio', matio_dep],
     'NIfTI load/save': ['libnifti', libnifti_found ? libnifti_dep : disabler()],
     'FITS load/save': ['cfitsio', cfitsio_dep],
     'GIF save': ['cgif', cgif_dep],
     'Magick @0@'.format('/'.join(get_option('magick-features'))): [get_option('magick-package'), magick_found ? magick_dep : disabler(), magick_module],
    },
}

# external_deps can have duplicates (eg. cairo can appear several times),
# which will make summary fail
seen_deps = []
foreach dep: external_deps + module_deps
    if dep.type_name() != 'internal' and dep.name() not in seen_deps
       summary(dep.name(), dep.version(), section: 'Dependencies')
       seen_deps += dep.name()
    endif
endforeach
foreach section_title, section : build_summary
    summary(section, bool_yn: true, section: section_title)
endforeach
foreach section_title, section: build_features
    foreach key, arr : section
        dep_name = arr[0]
        found = arr[1].found()
        if found and arr[1].type_name() != 'internal'
            dep_name = arr[1].name()
        endif
        dynamic_module = arr.length() > 2 ? [' (dynamic module: ', arr[2], ')'] : []
        summary('@0@ with @1@'.format(key, dep_name), [found] + dynamic_module, bool_yn: true, list_sep: '', section: section_title)
    endforeach
endforeach

subdir('libvips')
if get_option('docs')
  subdir('doc')
endif
if get_option('examples')
  subdir('examples')
endif
if get_option('cplusplus')
  subdir('cplusplus')
endif

# these lines removed by a regexp for oss-fuzz builds, don't touch!
subdir('man')
subdir('po')
subdir('tools')
subdir('test')
subdir('fuzz')
