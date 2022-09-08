examples = [
    'annotate-animated',
]

foreach example : examples
    executable(example,
        example + '.c',
        dependencies: libvips_dep,
    )
endforeach

