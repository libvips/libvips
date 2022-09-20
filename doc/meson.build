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
  'Using-vipsthumbnail.md',
  'multipage-and-animated-images.md',
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

custom_target('libvips-doc',
  input: vips_gir[0],
  output: 'Vips',
  command: [
    gidocgen,
    'generate',
    '--quiet',
    '--add-include-path=@0@'.format(vips_include_dir),
    '--config', meson.current_source_dir() / 'vips.toml',
    '--output-dir=@OUTPUT@',
    '--no-namespace-dir',
    '--content-dir=@0@'.format(meson.current_source_dir()),
    '@INPUT@',
  ],
  depend_files: ['vips.toml', vips_content_files],
  build_by_default: true,
  install: true,
  install_dir: get_option('prefix') / get_option('datadir') / 'doc'
)
