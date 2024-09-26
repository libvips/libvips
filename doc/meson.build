private_libvips_headers = [
    'arithmetic/binary.h',
    'arithmetic/hough.h',
    'arithmetic/nary.h',
    'arithmetic/parithmetic.h',
    'arithmetic/statistic.h',
    'arithmetic/unaryconst.h',
    'arithmetic/unary.h',
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
    'foreign/libnsgif/lzw.h',
    'foreign/libnsgif/nsgif.h',
    'foreign/libnsgif/test/cli.h',
    'foreign/magick.h',
    'foreign/pforeign.h',
    'foreign/quantise.h',
    'foreign/tiff.h',
    'freqfilt/pfreqfilt.h',
    'histogram/hist_unary.h',
    'histogram/phistogram.h',
    'include/vips/almostdeprecated.h',
    'include/vips/deprecated.h',
    'include/vips/dispatch.h',
    'include/vips/format.h',
    'include/vips/internal.h',
    'include/vips/intl.h',
    'include/vips/mask.h',
    'include/vips/private.h',
    'include/vips/thread.h',
    'include/vips/video.h',
    'include/vips/vips7compat.h',
    'iofuncs/sink.h',
    'morphology/pmorphology.h',
    'mosaicing/global_balance.h',
    'mosaicing/pmosaicing.h',
    'resample/presample.h',
    'resample/templates.h',
]

private_headers = []
foreach private_libvips_header : private_libvips_headers
    private_headers += [project_source_root / 'libvips' / private_libvips_header]
endforeach

markdown_content_files = files(
    'binding.md',
    'Cite.md',
    'Developer-checklist.md',
    'Examples.md',
    'How-it-opens-files.md',
    'How-it-works.md',
    'libvips-from-C++.md',
    'Making-image-pyramids.md',
    'Using-vipsthumbnail.md',
)

pandoc = find_program('pandoc', required: false)

if pandoc.found()
    # we have some files in markdown ... convert to docbook for gtk-doc
    gen = generator(pandoc,
        output: '@BASENAME@.xml',
        arguments: [
            '@INPUT@',
            '--template=@0@'.format(meson.current_source_dir() / 'pandoc-docbook-template.docbook'),
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
        'binding.xml',
        'Cite.xml',
        'Developer-checklist.xml',
        'Examples.xml',
        'How-it-opens-files.xml',
        'How-it-works.xml',
        'libvips-from-C++.xml',
        'Making-image-pyramids.xml',
        'Using-vipsthumbnail.xml',
    )
endif

content_files = files(
    'extending.xml',
    'file-format.xml',
    'function-list.xml',
    'using-command-line.xml',
    'using-C.xml',
    'using-threads.xml',
)

images = files(
    'images/Combine.png',
    'images/interconvert.png',
    'images/Memtrace.png',
    'images/owl.jpg',
    'images/Sequence.png',
    'images/Sink.png',
    'images/tn_owl.jpg',
    'images/Vips-smp.png',
)

version_conf = configuration_data()
version_conf.set('VIPS_VERSION', meson.project_version())
version_xml = configure_file(
    input: 'version.xml.in',
    output: '@BASENAME@',
    configuration: version_conf
)

glib_prefix = glib_dep.get_variable(pkgconfig: 'prefix')
docpath = get_option('prefix') / get_option('datadir') / 'gtk-doc' / 'html'

gnome.gtkdoc('libvips',
    main_xml: 'libvips-docs.xml',
    namespace: 'vips',
    src_dir: 'libvips',
    dependencies: libvips_dep,
    ignore_headers: private_headers,
    scan_args: [ '--rebuild-types' ],
    mkdb_args: [ '--default-includes=vips/vips.h' ],
    fixxref_args: [
        '--html-dir=@0@'.format(docpath),
        '--extra-dir=@0@'.format(glib_prefix / gnome.gtkdoc_html_dir('glib')),
        '--extra-dir=@0@'.format(glib_prefix / gnome.gtkdoc_html_dir('gobject')),
        '--extra-dir=@0@'.format(glib_prefix / gnome.gtkdoc_html_dir('gio')),
    ],
    content_files: [ content_files, markdown_content_files_docbook, version_xml ],
    expand_content_files: [ content_files ],
    html_assets: images,
    install: true
)
