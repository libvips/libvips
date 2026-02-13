if not get_option('tools')
    subdir_done()
endif

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
