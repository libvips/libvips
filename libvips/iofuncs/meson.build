iofuncs_sources = files(
    'ginputsource.c',
    'sourceginput.c',
    'connection.c',
    'source.c',
    'sourcecustom.c',
    'target.c',
    'targetcustom.c',
    'sbuf.c',
    'dbuf.c',
    'reorder.c',
    'type.c',
    'gate.c',
    'object.c',
    'error.c',
    'image.c',
    'vips.c',
    'generate.c',
    'mapfile.c',
    'cache.c',
    'sink.c',
    'sinkmemory.c',
    'sinkdisc.c',
    'sinkscreen.c',
    'memory.c',
    'header.c',
    'operation.c',
    'region.c',
    'rect.c',
    'semaphore.c',
    'threadpool.c',
    'util.c',
    'init.c',
    'buf.c',
    'window.c',
    'vector.c',
    'system.c',
    'buffer.c',
)

iofuncs_headers = files(
    'sink.h',
)

vipsmarshal = gnome.genmarshal(
    'vipsmarshal',
    prefix: 'vips',
    sources: 'vipsmarshal.list',
)

libvips_sources += iofuncs_sources

iofuncs_lib = static_library('iofuncs',
    iofuncs_sources,
    iofuncs_headers,
    vipsmarshal,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += iofuncs_lib
