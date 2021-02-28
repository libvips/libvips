# libnsgif

This is [libnsgif](https://www.netsurf-browser.org/projects/libnsgif/),
but within the libviops build system.

Based on libnsgif-0.2.1, with one patch to prevent it modifying the input 
buffer on error.

# To update

When netsurf release a new version:

* copy in sources
* reapply any patches from git, eg. no input modification

# To do

No attempt made to run tests or build docs.
