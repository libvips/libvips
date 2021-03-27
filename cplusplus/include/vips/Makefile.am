pkginclude_HEADERS = \
	VError8.h \
	VImage8.h \
	VInterpolate8.h \
	VConnection8.h \
	vips8 

vips-operators:
	echo "// headers for vips operations" > vips-operators; \
	echo "// paste this file into VImage8.h, do not leave in repo" > vips-operators; \
	echo -n "// " >> vips-operators; \
	date >> vips-operators; \
	echo "// this file is generated automatically, do not edit!" >> vips-operators; \
	./../../gen-operators.py -g h >> vips-operators
