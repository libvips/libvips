fuzz_deps = libvips_deps

# Links in a static library provided by OSS-Fuzz, else a standalone driver.
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh-script-environment
fuzzing_engine = cpp.find_library('FuzzingEngine', required: false)
if fuzzing_engine.found()
    fuzz_deps += fuzzing_engine
else
    standalone_engine = static_library('standalone_engine',
        'StandaloneFuzzTargetMain.c'
    )
    fuzz_deps += declare_dependency(link_with: standalone_engine)
endif

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
        dependencies: [libvips_dep, fuzz_deps]
    )
endforeach


# If the FuzzingEngine isn't available, build the unit tests to be run on CI
if not fuzzing_engine.found()
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
endif
