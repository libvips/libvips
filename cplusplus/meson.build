subdir('include/vips')

libvips_cpp_lib = library('vips-cpp',
    'VImage.cpp',
    'VInterpolate.cpp',
    'VRegion.cpp',
    'VConnection.cpp',
    'VError.cpp',
    dependencies: libvips_dep,
    include_directories: libvips_cpp_includedir,
    version: library_version,
    darwin_versions: darwin_versions,
    gnu_symbol_visibility: 'hidden',
    install: true,
)

libvips_cpp_dep = declare_dependency(
    link_with: libvips_cpp_lib,
    dependencies: libvips_dep,
    include_directories: libvips_cpp_includedir,
)

pkg.generate(
    libvips_cpp_lib,
    requires: [ libvips_lib, glib_dep, gobject_dep ],
    name: 'vips-cpp',
    description: 'C++ API for vips8 image processing library',
)

custom_target('vips-operators-header',
    command: [ 'gen-operators.py', '-g', 'h'],
    capture: true,
    output: 'vips-operators.h'
)

custom_target('vips-operators-source',
    command: [ 'gen-operators.py', '-g', 'cpp'],
    capture: true,
    output: 'vips-operators.cpp'
)

if get_option('doxygen')
    doxygen = find_program('doxygen')
    doxygen_data = configuration_data()
    doxygen_data.set('VIPS_MAJOR_VERSION', version_major)
    doxygen_data.set('VIPS_MINOR_VERSION', version_minor)
    doxygen_data.set('DOXY_INPUT_DIRECTORY', meson.current_source_dir())
    doxygen_data.set('DOXY_OUTPUT_DIRECTORY', 'cplusplus')

    doxyfile = configure_file(
        input: 'Doxyfile.in',
        output: 'Doxyfile',
        configuration: doxygen_data,
        install: false
    )

    html_target = custom_target('vips-cpp-docs',
        input: doxyfile,
        output: 'html',
        command: [doxygen, doxyfile],
        install: true,
        install_dir: get_option('prefix') / get_option('datadir') / 'doc' / 'vips-doc'
    )
endif
