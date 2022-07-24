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

install_data(
    'vipsprofile',
    install_dir: get_option('prefix') / get_option('bindir'),
    install_mode: 'rwxr-xr-x',
)
