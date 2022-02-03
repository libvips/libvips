arithmetic_sources = files(
    'find_trim.c',
    'sum.c',
    'hough.c',
    'hough_line.c',
    'hough_circle.c',
    'abs.c',
    'complex.c',
    'deviate.c',
    'divide.c',
    'measure.c',
    'getpoint.c',
    'multiply.c',
    'remainder.c',
    'sign.c',
    'statistic.c',
    'stats.c',
    'avg.c',
    'min.c',
    'max.c',
    'hist_find.c',
    'hist_find_ndim.c',
    'hist_find_indexed.c',
    'project.c',
    'profile.c',
    'subtract.c',
    'math.c',
    'arithmetic.c',
    'binary.c',
    'unary.c',
    'nary.c',
    'unaryconst.c',
    'relational.c',
    'boolean.c',
    'add.c',
    'linear.c',
    'invert.c',
    'math2.c',
    'round.c',
)

arithmetic_headers = files(
    'hough.h',
    'statistic.h',
    'parithmetic.h',
    'binary.h',
    'unary.h',
    'nary.h',
    'unaryconst.h'
)

libvips_sources += arithmetic_sources

arithmetic_lib = static_library('arithmetic',
    arithmetic_sources,
    arithmetic_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += arithmetic_lib
