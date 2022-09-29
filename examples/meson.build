examples = [
    'annotate-animated',
    'new-from-buffer',
    'progress-cancel',
    'use-vips-func',
]

foreach example : examples
    executable(example,
        example + '.c',
        dependencies: libvips_dep,
    )
endforeach

