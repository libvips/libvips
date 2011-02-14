
/* Generated data (by glib-mkenums) */

/* auto-generated enums for vips introspection */

#include <vips/vips.h>
/* enumerations from "../../libvips/include/vips/util.h" */
GType
vips_token_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_TOKEN_LEFT, "VIPS_TOKEN_LEFT", "left"},
			{VIPS_TOKEN_RIGHT, "VIPS_TOKEN_RIGHT", "right"},
			{VIPS_TOKEN_STRING, "VIPS_TOKEN_STRING", "string"},
			{VIPS_TOKEN_EQUALS, "VIPS_TOKEN_EQUALS", "equals"},
			{VIPS_TOKEN_COMMA, "VIPS_TOKEN_COMMA", "comma"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsToken", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/image.h" */
GType
vips_demand_style_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_DEMAND_STYLE_SMALLTILE, "VIPS_DEMAND_STYLE_SMALLTILE", "smalltile"},
			{VIPS_DEMAND_STYLE_FATSTRIP, "VIPS_DEMAND_STYLE_FATSTRIP", "fatstrip"},
			{VIPS_DEMAND_STYLE_THINSTRIP, "VIPS_DEMAND_STYLE_THINSTRIP", "thinstrip"},
			{VIPS_DEMAND_STYLE_ANY, "VIPS_DEMAND_STYLE_ANY", "any"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsDemandStyle", values );
	}

	return( etype );
}
GType
vips_type_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_TYPE_MULTIBAND, "VIPS_TYPE_MULTIBAND", "multiband"},
			{VIPS_TYPE_B_W, "VIPS_TYPE_B_W", "b-w"},
			{VIPS_TYPE_HISTOGRAM, "VIPS_TYPE_HISTOGRAM", "histogram"},
			{VIPS_TYPE_FOURIER, "VIPS_TYPE_FOURIER", "fourier"},
			{VIPS_TYPE_XYZ, "VIPS_TYPE_XYZ", "xyz"},
			{VIPS_TYPE_LAB, "VIPS_TYPE_LAB", "lab"},
			{VIPS_TYPE_CMYK, "VIPS_TYPE_CMYK", "cmyk"},
			{VIPS_TYPE_LABQ, "VIPS_TYPE_LABQ", "labq"},
			{VIPS_TYPE_RGB, "VIPS_TYPE_RGB", "rgb"},
			{VIPS_TYPE_UCS, "VIPS_TYPE_UCS", "ucs"},
			{VIPS_TYPE_LCH, "VIPS_TYPE_LCH", "lch"},
			{VIPS_TYPE_LABS, "VIPS_TYPE_LABS", "labs"},
			{VIPS_TYPE_sRGB, "VIPS_TYPE_sRGB", "srgb"},
			{VIPS_TYPE_YXY, "VIPS_TYPE_YXY", "yxy"},
			{VIPS_TYPE_RGB16, "VIPS_TYPE_RGB16", "rgb16"},
			{VIPS_TYPE_GREY16, "VIPS_TYPE_GREY16", "grey16"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsType", values );
	}

	return( etype );
}
GType
vips_format_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_FORMAT_NOTSET, "VIPS_FORMAT_NOTSET", "notset"},
			{VIPS_FORMAT_UCHAR, "VIPS_FORMAT_UCHAR", "uchar"},
			{VIPS_FORMAT_CHAR, "VIPS_FORMAT_CHAR", "char"},
			{VIPS_FORMAT_USHORT, "VIPS_FORMAT_USHORT", "ushort"},
			{VIPS_FORMAT_SHORT, "VIPS_FORMAT_SHORT", "short"},
			{VIPS_FORMAT_UINT, "VIPS_FORMAT_UINT", "uint"},
			{VIPS_FORMAT_INT, "VIPS_FORMAT_INT", "int"},
			{VIPS_FORMAT_FLOAT, "VIPS_FORMAT_FLOAT", "float"},
			{VIPS_FORMAT_COMPLEX, "VIPS_FORMAT_COMPLEX", "complex"},
			{VIPS_FORMAT_DOUBLE, "VIPS_FORMAT_DOUBLE", "double"},
			{VIPS_FORMAT_DPCOMPLEX, "VIPS_FORMAT_DPCOMPLEX", "dpcomplex"},
			{VIPS_FORMAT_LAST, "VIPS_FORMAT_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsFormat", values );
	}

	return( etype );
}
GType
vips_coding_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_CODING_NONE, "VIPS_CODING_NONE", "none"},
			{VIPS_CODING_LABQ, "VIPS_CODING_LABQ", "labq"},
			{VIPS_CODING_RAD, "VIPS_CODING_RAD", "rad"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsCoding", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/object.h" */
GType
vips_argument_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_ARGUMENT_NONE, "VIPS_ARGUMENT_NONE", "none"},
			{VIPS_ARGUMENT_REQUIRED, "VIPS_ARGUMENT_REQUIRED", "required"},
			{VIPS_ARGUMENT_CONSTRUCT, "VIPS_ARGUMENT_CONSTRUCT", "construct"},
			{VIPS_ARGUMENT_SET_ONCE, "VIPS_ARGUMENT_SET_ONCE", "set-once"},
			{VIPS_ARGUMENT_INPUT, "VIPS_ARGUMENT_INPUT", "input"},
			{VIPS_ARGUMENT_OUTPUT, "VIPS_ARGUMENT_OUTPUT", "output"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsArgument", values );
	}

	return( etype );
}

/* Generated data ends here */

