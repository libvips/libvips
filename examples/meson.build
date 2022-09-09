examples = [
    'annotate-animated',
    'new-from-buffer',
    'progress-cancel',
]

foreach example : examples
    executable(example,
        example + '.c',
        dependencies: libvips_dep,
    )
endforeach

