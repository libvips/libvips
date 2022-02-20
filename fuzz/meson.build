standaloneengine = static_library('standaloneengine',
    'StandaloneFuzzTargetMain.c',
    dependencies: libvips_deps,
)

fuzz_progs = [
    'jpegsave_file_fuzzer',
    'jpegsave_buffer_fuzzer',
    'pngsave_buffer_fuzzer',
    'webpsave_buffer_fuzzer',
    'gifsave_buffer_fuzzer',
    'sharpen_fuzzer',
    'thumbnail_fuzzer',
    'smartcrop_fuzzer',
    'mosaic_fuzzer'
]

fuzz_execs = []
foreach fuzz_prog : fuzz_progs
    fuzz_execs += executable(fuzz_prog,
        fuzz_prog + '.cc',
        dependencies: libvips_dep,
        link_with: standaloneengine
    )
endforeach

test_fuzz = configure_file(
    input: 'test_fuzz.sh',
    output: 'test_fuzz.sh',
    copy: true,
)

test(
    'fuzz',
    test_fuzz,
    workdir: meson.current_build_dir(),
    depends: [
        fuzz_execs,
    ],
    # Increase the timeout as running the tests with sanitizers
    # enabled could be slower than the default 30 seconds.
    timeout: 60,
)
