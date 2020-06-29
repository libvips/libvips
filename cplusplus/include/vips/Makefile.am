pkginclude_HEADERS = \
	VError8.h \
	VImage8.h \
	VInterpolate8.h \
	VConnection8.h \
	vips8 \
	vips-operators.h 

vips-operators.h:
	echo "// headers for vips operations" > vips-operators.h; \
	echo -n "// " >> vips-operators.h; \
	date >> vips-operators.h; \
	echo "// this file is generated automatically, do not edit!" >> vips-operators.h; \
	./../../gen-operators.py -g h >> vips-operators.h
