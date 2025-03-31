gidocgen = find_program('gi-docgen')

if not enable_introspection
  error('API reference requires introspection.')
endif

docs_dir = get_option('prefix') / get_option('datadir') / 'doc'

vips_content_files = files(
  'binding.md',
  'cite.md',
  'developer-checklist.md',
  'examples.md',
  'extending.md',
  'file-format.md',
  'function-list.md',
  'how-it-opens-files.md',
  'how-it-works.md',
  'libvips-arithmetic.md',
  'libvips-header.md',
  'making-image-pyramids.md',
  'multipage-and-animated-images.md',
  'using-from-c.md',
  'using-from-cplusplus.md',
  'using-the-cli.md',
  'using-threads.md',
  'using-vipsthumbnail.md',
)

vips_include_dir = meson.current_build_dir() / 'libvips' / 'include'
doc_conf = configuration_data()
doc_conf.set('VIPS_VERSION', '@0@.@1@'.format(version_major, version_minor))

vips_toml = configure_file(
  input: 'vips.toml.in',
  output: 'vips.toml',
  configuration: doc_conf,
  install: true,
  install_dir: docs_dir / 'vips',
)

fixup_gir_for_doc = find_program('fixup-gir-for-doc.py')

vips_gir_doc = custom_target(
  input: vips_gir[0],
  output: 'Vips-@0@.0-doc.gir'.format(version_major),
  command: [fixup_gir_for_doc, '@INPUT@', '@OUTPUT@'],
)

custom_target('libvips-doc',
  input: [vips_toml, vips_gir_doc],
  output: 'vips',
  command: [
    gidocgen,
    'generate',
    '--quiet',
    '--no-namespace-dir',
    '--add-include-path=@0@'.format(vips_include_dir),
    '--config=@INPUT0@',
    '--output-dir=@OUTPUT@',
    '--content-dir=@0@'.format(meson.current_source_dir()),
    '@INPUT1@',
  ],
  depends: vips_gir[0],
  depend_files: vips_content_files,
  build_by_default: true,
  install: true,
  install_dir: docs_dir
)

test('doc-check-vips',
  gidocgen,
  args: [
    'check',
    '--config', vips_toml,
    '--add-include-path=@0@'.format(vips_include_dir),
    vips_gir[0],
  ],
  depends: vips_gir[0],
  # FIXME: Remove once we have documented all public-facing symbols,
  # parameters and return values.
  should_fail: true,
  suite: ['docs'],
)
