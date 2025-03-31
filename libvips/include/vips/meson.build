# Headers that we install but neither introspect nor document.
public_other_headers = files(
    'debug.h',
    'format.h',
    'private.h',
    'transform.h',
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
    'buf.h',
    'colour.h',
    'connection.h',
    'conversion.h',
    'convolution.h',
    'create.h',
    'dbuf.h',
    'draw.h',
    'error.h',
    'foreign.h',
    'freqfilt.h',
    'gate.h',
    'generate.h',
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
    'sbuf.h',
    'semaphore.h',
    'thread.h',
    'threadpool.h',
    'type.h',
    'util.h',
    'vector.h',
    'vips.h',
)

enum_headers = files(
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
)

if get_option('deprecated')
    enum_headers += files(
        'almostdeprecated.h',
    )
endif

enumtypes = gnome.mkenums(
    'enumtypes',
    sources: enum_headers,
    h_template: 'enumtypes.h.in',
    c_template: 'enumtypes.c.in',
    install_header: true,
    install_dir: get_option('prefix') / get_option('includedir') / 'vips'
)

vips_verbose_config = []
foreach _, section : build_summary
    foreach key, arr : section
        if key.contains('docs') or \
           key.contains('cpp-docs') or \
           key.contains('introspection') or \
           key.contains('examples')
           continue
        endif

        vips_verbose_config += '@0@: @1@'.format(key, arr[0])
    endforeach
endforeach
foreach _, section : build_features
    foreach key, arr : section
        dep_name = arr[0]
        found = arr[1].found()
        if found and arr[1].type_name() != 'internal'
            dep_name = arr[1].name()
        endif
        dynamic_module = arr.length() > 2 ? ' (dynamic module: @0@)'.format(arr[2]) : ''
        vips_verbose_config += '@0@ with @1@: @2@@3@'.format(key, dep_name, found, dynamic_module)
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
