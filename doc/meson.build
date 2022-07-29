private_libvips_headers = [
    'include/vips/almostdeprecated.h',
    'include/vips/deprecated.h',
    'include/vips/vips7compat.h',
    'include/vips/dispatch.h',
    'include/vips/internal.h',
    'include/vips/thread.h',
    'include/vips/intl.h',
    'include/vips/format.h',
    'include/vips/mask.h',
    'include/vips/private.h',
    'include/vips/video.h',
# ignore all .h files in libvips/*, these are internal
    'arithmetic/binary.h',
    'arithmetic/hough.h',
    'arithmetic/nary.h',
    'arithmetic/parithmetic.h',
    'arithmetic/statistic.h',
    'arithmetic/unary.h',
    'arithmetic/unaryconst.h',
    'colour/pcolour.h',
    'colour/profiles.h',
    'conversion/bandary.h',
    'conversion/pconversion.h',
    'convolution/correlation.h',
    'convolution/pconvolution.h',
    'create/pcreate.h',
    'create/pmask.h',
    'create/point.h',
    'draw/drawink.h',
    'draw/pdraw.h',
    'foreign/dbh.h',
    'foreign/jpeg.h',
    'foreign/magick.h',
    'foreign/pforeign.h',
    'foreign/quantise.h',
    'foreign/tiff.h',
    'foreign/libnsgif/lzw.h',
    'foreign/libnsgif/nsgif.h',
    'foreign/libnsgif/test/cli.h',
    'freqfilt/pfreqfilt.h',
    'histogram/hist_unary.h',
    'histogram/phistogram.h',
    'iofuncs/sink.h',
    'morphology/pmorphology.h',
    'mosaicing/global_balance.h',
    'mosaicing/pmosaicing.h',
    'resample/presample.h',
    'resample/templates.h'
]

private_headers = []
foreach private_libvips_header : private_libvips_headers
    private_headers += [join_paths(meson.project_source_root(), 'libvips', private_libvips_header)]
endforeach

markdown_content_files = files(
    'How-it-works.md',
    'libvips-from-C++.md',
    'Using-vipsthumbnail.md',
    'How-it-opens-files.md',
    'Examples.md',
    'Cite.md',
    'binding.md',
    'Making-image-pyramids.md',
)

pandoc = find_program('pandoc', required: false)

if pandoc.found()
    # we have some files in markdown ... convert to docbook for gtk-doc
    gen = generator(pandoc,
        output: '@BASENAME@.xml',
        arguments: [
            '@INPUT@',
            '--template=@0@'.format(join_paths(meson.current_source_dir(), 'pandoc-docbook-template.docbook')),
            '--wrap=none',
            '-V', 'title=@BASENAME@',
            '-f', 'markdown+smart',
            '-t', 'docbook',
            '-o', '@OUTPUT@',
        ]
    )

    markdown_content_files_generated = gen.process(markdown_content_files)

    # pandoc makes section headers, we want refsect3 for gtk-doc
    markdown_content_files_docbook = custom_target('gen-docs',
        output: 'generated',
        input: markdown_content_files_generated,
        command: [ 'sed', '-i', '-e', 's|<section|<refsect3|g', '-e', 's|</section|</refsect3|g', '@INPUT@' ],
        build_by_default: true
    )
else
    # use the pre-generated docbook files when pandoc is not available
    markdown_content_files_docbook = files(
        'How-it-works.xml',
        'libvips-from-C++.xml',
        'Using-vipsthumbnail.xml',
        'How-it-opens-files.xml',
        'Examples.xml',
        'Cite.xml',
        'binding.xml',
        'Making-image-pyramids.xml',
    )
endif

content_files = files(
    'using-command-line.xml',
    'using-C.xml',
    'using-threads.xml',
    'extending.xml',
    'function-list.xml',
    'file-format.xml',
)

images = files(
    'images/owl.jpg',
    'images/tn_owl.jpg',
    'images/interconvert.png',
    'images/Combine.png',
    'images/Memtrace.png',
    'images/Sequence.png',
    'images/Sink.png',
    'images/Vips-smp.png',
)

version_conf = configuration_data()
version_conf.set('VIPS_VERSION', meson.project_version ())
vips_docs = configure_file(input: 'libvips-docs.xml.in', output: 'libvips-docs.xml', configuration: version_conf)

glib_prefix = glib_dep.get_variable(pkgconfig: 'prefix')
glib_docpath = glib_prefix / 'share' / 'gtk-doc' / 'html'
docpath = get_option('prefix') / get_option('datadir') / 'gtk-doc' / 'html'

gnome.gtkdoc('libvips',
    mode: 'none',
    main_xml: 'libvips-docs.xml.in',
    src_dir: [
        join_paths(meson.project_source_root(), 'libvips'),
        join_paths(meson.project_build_root(), 'libvips'),
    ],
    dependencies: libvips_dep,
    scan_args: [
        '--ignore-headers=' + ' '.join(private_headers),
        '--rebuild-types',
    ],
    mkdb_args: [ '--default-includes=vips/vips.h' ],
    fixxref_args: [
        '--html-dir=@0@'.format(docpath),
        '--extra-dir=@0@'.format(join_paths(glib_docpath, 'glib')),
        '--extra-dir=@0@'.format(join_paths(glib_docpath, 'gobject')),
        '--extra-dir=@0@'.format(join_paths(glib_docpath, 'gio')),
    ],
    content_files: [ content_files, markdown_content_files_docbook ],
    expand_content_files: [ content_files ],
    html_assets: images,
    install: true
)
