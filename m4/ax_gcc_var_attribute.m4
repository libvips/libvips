# ===========================================================================
#   https://www.gnu.org/software/autoconf-archive/ax_gcc_var_attribute.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_GCC_VAR_ATTRIBUTE(ATTRIBUTE)
#
# DESCRIPTION
#
#   This macro checks if the compiler supports one of GCC's variable
#   attributes; many other compilers also provide variable attributes with
#   the same syntax. Compiler warnings are used to detect supported
#   attributes as unsupported ones are ignored by default so quieting
#   warnings when using this macro will yield false positives.
#
#   The ATTRIBUTE parameter holds the name of the attribute to be checked.
#
#   If ATTRIBUTE is supported define HAVE_VAR_ATTRIBUTE_<ATTRIBUTE>.
#
#   The macro caches its result in the ax_cv_have_var_attribute_<attribute>
#   variable.
#
#   The macro currently supports the following variable attributes:
#
#    aligned
#    cleanup
#    common
#    nocommon
#    deprecated
#    mode
#    packed
#    tls_model
#    unused
#    used
#    vector_size
#    weak
#    dllimport
#    dllexport
#    init_priority
#
#   Unsupported variable attributes will be tested against a global integer
#   variable and without any arguments given to the attribute itself; the
#   result of this check might be wrong or meaningless so use with care.
#
# LICENSE
#
#   Copyright (c) 2013 Gabriele Svelto <gabriele.svelto@gmail.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.  This file is offered as-is, without any
#   warranty.

#serial 5

AC_DEFUN([AX_GCC_VAR_ATTRIBUTE], [
    AS_VAR_PUSHDEF([ac_var], [ax_cv_have_var_attribute_$1])

    AC_CACHE_CHECK([for __attribute__(($1))], [ac_var], [
        AC_LINK_IFELSE([AC_LANG_PROGRAM([
            m4_case([$1],
                [aligned], [
                    int foo __attribute__(($1(32)));
                ],
                [cleanup], [
                    int bar(int *t) { return *t; };
                ],
                [common], [
                    int foo __attribute__(($1));
                ],
                [nocommon], [
                    int foo __attribute__(($1));
                ],
                [deprecated], [
                    int foo __attribute__(($1)) = 0;
                ],
                [mode], [
                    long foo __attribute__(($1(word)));
                ],
                [packed], [
                    struct bar {
                        int baz __attribute__(($1));
                    };
                ],
                [tls_model], [
                    __thread int bar1 __attribute__(($1("global-dynamic")));
                    __thread int bar2 __attribute__(($1("local-dynamic")));
                    __thread int bar3 __attribute__(($1("initial-exec")));
                    __thread int bar4 __attribute__(($1("local-exec")));
                ],
                [unused], [
                    int foo __attribute__(($1));
                ],
                [used], [
                    int foo __attribute__(($1));
                ],
                [vector_size], [
                    int foo __attribute__(($1(16)));
                ],
                [weak], [
                    int foo __attribute__(($1));
                ],
                [dllimport], [
                    int foo __attribute__(($1));
                ],
                [dllexport], [
                    int foo __attribute__(($1));
                ],
                [init_priority], [
                    struct bar { bar() {} ~bar() {} };
                    bar b __attribute__(($1(65535/2)));
                ],
                [
                 m4_warn([syntax], [Unsupported attribute $1, the test may fail])
                 int foo __attribute__(($1));
                ]
            )], [
            m4_case([$1],
                [cleanup], [
                    int foo __attribute__(($1(bar))) = 0;
                    foo = foo + 1;
                ],
                []
            )])
            ],
            dnl GCC doesn't exit with an error if an unknown attribute is
            dnl provided but only outputs a warning, so accept the attribute
            dnl only if no warning were issued.
            [AS_IF([test -s conftest.err],
                [AS_VAR_SET([ac_var], [no])],
                [AS_VAR_SET([ac_var], [yes])])],
            [AS_VAR_SET([ac_var], [no])])
    ])

    AS_IF([test yes = AS_VAR_GET([ac_var])],
        [AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_VAR_ATTRIBUTE_$1), 1,
            [Define to 1 if the system has the `$1' variable attribute])], [])

    AS_VAR_POPDEF([ac_var])
])
