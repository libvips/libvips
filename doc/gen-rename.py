#!/usr/bin/python3

from pyvips import Introspect, Operation, Error, \
    ffi, type_map, type_from_name, nickname_find

# for VipsOperationFlags
_OPERATION_DEPRECATED = 8


def gen_rename_list():
    all_nicknames = []

    def add_nickname(gtype, a, b):
        nickname = nickname_find(gtype)
        try:
            # can fail for abstract types
            intro = Introspect.get(nickname)

            # we are only interested in non-deprecated operations
            if (intro.flags & _OPERATION_DEPRECATED) == 0:
                all_nicknames.append(nickname)
        except Error:
            pass

        type_map(gtype, add_nickname)

        return ffi.NULL

    type_map(type_from_name('VipsOperation'), add_nickname)

    # make list unique and sort
    all_nicknames = list(set(all_nicknames))
    all_nicknames.sort()

    for nickname in all_nicknames:
        print(f"s/vips_\({nickname}\)()/[method@Image.\\1]/g")


if __name__ == '__main__':
    gen_rename_list()
