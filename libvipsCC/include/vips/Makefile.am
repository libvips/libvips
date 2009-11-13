pkginclude_HEADERS = \
	VDisplay.h \
	VError.h \
	VImage.h \
	VMask.h \
	vipscpp.h \
	vips \
	vipsc++.h 

.PHONEY:
vipsc++.h:
	packages=`vips --list packages | \
	  awk '{if($$1!="deprecated") print $$1}'` ; \
	  echo > vipsc++.h ; \
	  for name in $$packages; do \
	    echo "// headers for package $$name" >> vipsc++.h ; \
	    vips --cpph $$name >> vipsc++.h ; \
	    echo >> vipsc++.h ; \
	  done 
