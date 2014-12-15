vips_overridesdir = $(pyoverridesdir)
vips_overrides_PYTHON = Vips.py 

EXTRA_DIST = \
	README.md

# if we build in a separate tree, we need to symlink the *.py files from the
# source tree; Python does not accept the extensions and modules in different
# paths
build_pylinks:
	for f in $(vips_overrides_PYTHON); do \
	    [ -e $(builddir)/$$f ] || $(LN_S) $(srcdir)/$$f $(builddir)/$$f; \
	done

all-local: build_pylinks
check-local: build_pylinks

