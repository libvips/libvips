gidocgen = find_program('gi-docgen', required: get_option('gtk_doc'))

vips_content_files = [
  'binding.md',
  'Cite.md',
  'Developer-checklist.md',
  'Examples.md',
  'How-it-opens-files.md',
  'How-it-works.md',
  'libvips-from-C++.md',
  'Making-image-pyramids.md',
  'multipage-and-animated-images.md',
  'using-command-line.md',
  'using-threads.md', 
  'Using-vipsthumbnail.md',
  'images/Combine.png',
  'images/interconvert.png',
  'images/interconvert.svg',
  'images/Memtrace.png',
  'images/owl.jpg',
  'images/Sequence.png',
  'images/Sink.png',
  'images/tn_owl.jpg',
  'images/Vips-smp.png',
]

vips_include_dir = meson.current_build_dir() / 'libvips' / 'include'
doc_conf = configuration_data()
doc_conf.set('VIPS_VERSION', version_major + '.' + version_minor)

vips_toml = configure_file(input: 'vips.toml.in',
  output: 'vips.toml',
  configuration: doc_conf)

custom_target('libvips-doc',
  input: vips_gir[0],
  output: 'Vips',
  command: [
    gidocgen,
    'generate',
    '--quiet',
    '--add-include-path=@0@'.format(vips_include_dir),
    '--config', vips_toml,
    '--output-dir=@OUTPUT@',
    '--no-namespace-dir',
    '--content-dir=@0@'.format(meson.current_source_dir()),
    '@INPUT@',
  ],
  depend_files: [vips_toml, vips_content_files],
  build_by_default: true,
  install: true,
  install_dir: get_option('prefix') / get_option('datadir') / 'doc'
)
