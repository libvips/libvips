fuzz_deps = libvips_deps
fuzz_ldflags = []

if get_option('fuzzer_ldflags') != ''
    fuzz_ldflags += [get_option('fuzzer_ldflags')]
endif

if fuzzing_engine == 'none'
    standalone_engine = static_library('standalone_engine',
        'StandaloneFuzzTargetMain.c'
    )
    fuzz_deps += declare_dependency(link_with: standalone_engine)
elif fuzzing_engine == 'libfuzzer'
    fuzz_ldflags += ['-fsanitize=fuzzer']
endif

fuzz_progs = [
    'sharpen_fuzzer',
    'thumbnail_fuzzer',
    'smartcrop_fuzzer',
    'mosaic_fuzzer'
]

if libjpeg_dep.found()
    fuzz_progs += ['jpegsave_file_fuzzer']
endif

fuzz_execs = []
foreach fuzz_prog : fuzz_progs
    fuzz_execs += executable(fuzz_prog,
        fuzz_prog + '.cc',
        dependencies: [libvips_dep, fuzz_deps],
        link_args: fuzz_ldflags
    )
endforeach

fuzz_save_buffer_progs = {
    'csvsave': '.csv',
    'matrixsave': '.mat',
    'rawsave': '.raw',
    # vipssave requires a associated filename
    # https://github.com/libvips/libvips/discussions/2051
    # 'vipssave': '.vips',
}

if get_option('radiance')
    fuzz_save_buffer_progs += {'radsave': '.hdr'}
endif
if get_option('ppm')
    fuzz_save_buffer_progs += {'ppmsave': '.ppm'}
endif
if libjpeg_dep.found()
    fuzz_save_buffer_progs += {'jpegsave': '.jpg'}
endif
if libjxl_found
    fuzz_save_buffer_progs += {'jxlsave': '.jxl'}
endif
if libopenjp2_dep.found()
    fuzz_save_buffer_progs += {'jp2ksave': '.jp2'}
endif
if png_package.found()
    fuzz_save_buffer_progs += {'pngsave': '.png'}
endif
if libtiff_dep.found()
    fuzz_save_buffer_progs += {'tiffsave': '.tiff'}
endif
if libarchive_dep.found()
    fuzz_save_buffer_progs += {'dzsave': '.dz'}
endif
if libheif_dep.found()
    fuzz_save_buffer_progs += {'heifsave': '.avif'}
endif
if libwebp_dep.found()
    fuzz_save_buffer_progs += {'webpsave': '.webp'}
endif
# niftisave and fitssave is missing a buffer saver
# https://github.com/libvips/libvips/discussions/2051
# if libnifti_found
#     fuzz_save_buffer_progs += {'niftisave': '.nii'}
# endif
# if cfitsio_dep.found()
#     fuzz_save_buffer_progs += {'fitssave': '.fits'}
# endif
if cgif_dep.found()
    fuzz_save_buffer_progs += {'gifsave': '.gif'}
endif
if magick_found and 'save' in get_option('magick-features')
    fuzz_save_buffer_progs += {'magicksave': '.bmp'}
endif

foreach fuzz_basename, fuzz_save_suffix : fuzz_save_buffer_progs
    fuzz_execs += executable(fuzz_basename + '_buffer_fuzzer',
        'generic_buffer_fuzzer.cc',
        dependencies: [libvips_dep, fuzz_deps],
        link_args: fuzz_ldflags,
        cpp_args: '-DSAVE_SUFFIX="@0@"'.format(fuzz_save_suffix)
    )
endforeach


fuzz_execs += executable('generic_buffer_with_args_fuzzer',
    'generic_buffer_with_args_fuzzer.cc',
    dependencies: [libvips_dep, fuzz_deps],
    link_args: fuzz_ldflags,
)

# If the fuzzing engine is not OSS-Fuzz, build the unit tests to be run on CI
if fuzzing_engine != 'oss-fuzz'
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
        timeout: 120,
    )
endif
