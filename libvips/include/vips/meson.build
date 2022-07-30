public_other_headers = files(
    'buf.h',
    'connection.h',
    'dbuf.h',
    'debug.h',
    'format.h',
    'gate.h',
    'generate.h',
    'private.h',
    'sbuf.h',
    'semaphore.h',
    'thread.h',
    'threadpool.h',
    'transform.h',
    'util.h',
    'vector.h',
)

public_deprecated_headers = files(
    'almostdeprecated.h',
    'deprecated.h',
    'dispatch.h',
    'intl.h',
    'mask.h',
    'video.h',
    'vips7compat.h',
)

if get_option('deprecated')
    public_other_headers += public_deprecated_headers
endif

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
foreach _, section : build_summary
    foreach key, arr : section
        if key.contains('gtk-doc') or \
           key.contains('doxygen') or \
           key.contains('introspection')
           continue
        endif

        vips_verbose_config += '@0@: @1@@2@@3@@4@'.format(key, arr[0],
            arr.length() > 1 ? arr[1] : '',
            arr.length() > 2 ? arr[2] : '',
            arr.length() > 3 ? arr[3] : '')
    endforeach
endforeach

version_data = configuration_data()
version_data.set('VIPS_VERSION', meson.project_version())
version_data.set('VIPS_VERSION_STRING', meson.project_version())
version_data.set('VIPS_MAJOR_VERSION', version_major)
version_data.set('VIPS_MINOR_VERSION', version_minor)
version_data.set('VIPS_MICRO_VERSION', version_patch)
version_data.set('LIBRARY_CURRENT', library_current)
version_data.set('LIBRARY_REVISION', library_revision)
version_data.set('LIBRARY_AGE', library_age)
version_data.set('VIPS_CONFIG', '\\n'.join(vips_verbose_config))
version_data.set10('VIPS_ENABLE_DEPRECATED', get_option('deprecated'))

version_header = configure_file(
    input: 'version.h.in',
    output: 'version.h',
    configuration: version_data,
    install: true,
    install_dir: get_option('prefix') / get_option('includedir') / 'vips'
)

libvips_sources += public_headers
libvips_sources += enumtypes
libvips_sources += version_header

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
    ],
    include_directories: libvips_includedir
)

libvips_deps += libvips_headers_dep
