pkginclude_HEADERS = \
	VError8.h \
	VImage8.h \
	vips8 \
	vips-operators.h 

# swap the 'awk' line for this:
# awk '{if($$1!="deprecated") print $$1}'` ; \
# to not generate the wrappers for deprecated functions
vips-operators.h:
	packages=`vips list packages | \
	  awk '{print $$1}'` ; \
	  echo > vips-operators.h ; \
	  for name in $$packages; do \
	    echo "// headers for package $$name" >> vips-operators.h ; \
	    vips cpph $$name >> vips-operators.h ; \
	    echo >> vips-operators.h ; \
	  done 
