pkginclude_HEADERS = \
	VDisplay.h \
	VError.h \
	VImage.h \
	VMask.h \
	vipscpp.h \
	vips \
	vipsc++.h 

# swap the 'awk' line for this:
# awk '{if($$1!="deprecated") print $$1}'` ; \
# to not generate the wrappers for deprecated functions
vipsc++.h:
	packages=`vips list packages | \
	  awk '{print $$1}'` ; \
	  echo > vipsc++.h ; \
	  for name in $$packages; do \
	    echo "// headers for package $$name" >> vipsc++.h ; \
	    vips cpph $$name >> vipsc++.h ; \
	    echo >> vipsc++.h ; \
	  done 
