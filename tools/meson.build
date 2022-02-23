tools = [
    'vips',
    'vipsedit',
    'vipsthumbnail',
    'vipsheader'
]

foreach tool : tools
    executable(tool,
        tool + '.c',
        dependencies: libvips_dep,
        install: true
    )
endforeach

scripts = [
    'light_correct.in',
    'shrink_width.in',
    'batch_image_convert.in',
    'batch_rubber_sheet.in',
    'batch_crop.in',
]

script_data = configuration_data()
script_data.set('prefix', get_option('prefix'))
foreach script : scripts
    configure_file(
        input: script,
        output: '@BASENAME@',
        install: true,
        install_dir: get_option('prefix') / get_option('bindir'),
        install_mode: 'rwxr-xr-x',
        configuration: script_data
    )
endforeach

install_data(
    'vipsprofile',
    'vips-8.13',
    install_dir: get_option('prefix') / get_option('bindir'),
    install_mode: 'rwxr-xr-x',
)
