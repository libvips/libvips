variables_data = configuration_data()
variables_data.set('abs_top_srcdir', project_source_root)
variables_data.set('abs_top_builddir', project_build_root)
variables_data.set('PYTHON', pymod.find_installation().full_path())

variables_sh = configure_file(
    input: 'variables.sh.in',
    output: '@BASENAME@',
    configuration: variables_data
)

script_tests = [
    'cli',
    'formats',
    'seq',
    'stall',
    'threading',
    'keep'
]

foreach script_test : script_tests
    test(script_test,
        files('test_' + script_test + '.sh'),
        workdir: meson.current_build_dir(),
        # Increase the timeout as running the tests with sanitizers
        # enabled could be slower than the default 30 seconds.
        timeout: 120,
    )
endforeach

test_token = executable('test_token',
    'test_token.c',
    dependencies: libvips_dep,
)

test_token_sh = configure_file(
    input: 'test_token.sh',
    output: 'test_token.sh',
    copy: true,
)

test('token',
    test_token_sh,
    depends: test_token,
    workdir: meson.current_build_dir(),
)

test_connections = executable('test_connections',
    'test_connections.c',
    dependencies: libvips_dep,
)

test_connections_sh = configure_file(
    input: 'test_connections.sh',
    output: 'test_connections.sh',
    copy: true,
)

test('connections',
    test_connections_sh,
    depends: test_connections,
    workdir: meson.current_build_dir(),
)

test_descriptors = executable('test_descriptors',
    'test_descriptors.c',
    dependencies: libvips_dep,
)

test_descriptors_sh = configure_file(
    input: 'test_descriptors.sh',
    output: 'test_descriptors.sh',
    copy: true,
)

test('descriptors',
    test_descriptors_sh,
    depends: test_descriptors,
    workdir: meson.current_build_dir(),
)

test_timeout_webpsave = executable('test_timeout_webpsave',
    'test_timeout_webpsave.c',
    dependencies: libvips_dep,
)

test('webpsave_timeout',
    test_timeout_webpsave,
    depends: test_timeout_webpsave,
    workdir: meson.current_build_dir(),
)

test_timeout_gifsave = executable('test_timeout_gifsave',
    'test_timeout_gifsave.c',
    dependencies: libvips_dep,
)

test('gifsave_timeout',
    test_timeout_gifsave,
    depends: test_timeout_gifsave,
    workdir: meson.current_build_dir(),
)
