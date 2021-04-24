# libnsgif

This is [libnsgif](https://www.netsurf-browser.org/projects/libnsgif/),
but within the libvips build system. 

# To update

Run `./update.sh` to update this copy of libnsgif from the upstream repo. It
will also patch libnsgif.c to prevent it modifying the input.

Last updated 28 Feb 2021.

# To do

No attempt made to run tests or build docs. Though the gif loader is tested as
part of the libvips test suite.
