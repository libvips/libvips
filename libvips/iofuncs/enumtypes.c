
/* Generated data (by glib-mkenums) */

/* auto-generated enums for vips introspection */

#include <vips/vips.h>
/* enumerations from "../../libvips/include/vips/conversion.h" */
GType
vips_extend_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_EXTEND_BLACK, "VIPS_EXTEND_BLACK", "black"},
			{VIPS_EXTEND_COPY, "VIPS_EXTEND_COPY", "copy"},
			{VIPS_EXTEND_REPEAT, "VIPS_EXTEND_REPEAT", "repeat"},
			{VIPS_EXTEND_MIRROR, "VIPS_EXTEND_MIRROR", "mirror"},
			{VIPS_EXTEND_WHITE, "VIPS_EXTEND_WHITE", "white"},
			{VIPS_EXTEND_LAST, "VIPS_EXTEND_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsExtend", values );
	}

	return( etype );
}
GType
vips_direction_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_DIRECTION_HORIZONTAL, "VIPS_DIRECTION_HORIZONTAL", "horizontal"},
			{VIPS_DIRECTION_VERTICAL, "VIPS_DIRECTION_VERTICAL", "vertical"},
			{VIPS_DIRECTION_LAST, "VIPS_DIRECTION_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsDirection", values );
	}

	return( etype );
}
GType
vips_align_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_ALIGN_LOW, "VIPS_ALIGN_LOW", "low"},
			{VIPS_ALIGN_CENTRE, "VIPS_ALIGN_CENTRE", "centre"},
			{VIPS_ALIGN_HIGH, "VIPS_ALIGN_HIGH", "high"},
			{VIPS_ALIGN_LAST, "VIPS_ALIGN_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsAlign", values );
	}

	return( etype );
}
GType
vips_angle_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_ANGLE_0, "VIPS_ANGLE_0", "0"},
			{VIPS_ANGLE_90, "VIPS_ANGLE_90", "90"},
			{VIPS_ANGLE_180, "VIPS_ANGLE_180", "180"},
			{VIPS_ANGLE_270, "VIPS_ANGLE_270", "270"},
			{VIPS_ANGLE_LAST, "VIPS_ANGLE_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsAngle", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/arithmetic.h" */
GType
vips_operation_math_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_MATH_SIN, "VIPS_OPERATION_MATH_SIN", "sin"},
			{VIPS_OPERATION_MATH_COS, "VIPS_OPERATION_MATH_COS", "cos"},
			{VIPS_OPERATION_MATH_TAN, "VIPS_OPERATION_MATH_TAN", "tan"},
			{VIPS_OPERATION_MATH_ASIN, "VIPS_OPERATION_MATH_ASIN", "asin"},
			{VIPS_OPERATION_MATH_ACOS, "VIPS_OPERATION_MATH_ACOS", "acos"},
			{VIPS_OPERATION_MATH_ATAN, "VIPS_OPERATION_MATH_ATAN", "atan"},
			{VIPS_OPERATION_MATH_LOG, "VIPS_OPERATION_MATH_LOG", "log"},
			{VIPS_OPERATION_MATH_LOG10, "VIPS_OPERATION_MATH_LOG10", "log10"},
			{VIPS_OPERATION_MATH_EXP, "VIPS_OPERATION_MATH_EXP", "exp"},
			{VIPS_OPERATION_MATH_EXP10, "VIPS_OPERATION_MATH_EXP10", "exp10"},
			{VIPS_OPERATION_MATH_LAST, "VIPS_OPERATION_MATH_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationMath", values );
	}

	return( etype );
}
GType
vips_operation_math2_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_MATH2_POW, "VIPS_OPERATION_MATH2_POW", "pow"},
			{VIPS_OPERATION_MATH2_WOP, "VIPS_OPERATION_MATH2_WOP", "wop"},
			{VIPS_OPERATION_MATH2_LAST, "VIPS_OPERATION_MATH2_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationMath2", values );
	}

	return( etype );
}
GType
vips_operation_round_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_ROUND_NEAREST, "VIPS_OPERATION_ROUND_NEAREST", "nearest"},
			{VIPS_OPERATION_ROUND_CEIL, "VIPS_OPERATION_ROUND_CEIL", "ceil"},
			{VIPS_OPERATION_ROUND_FLOOR, "VIPS_OPERATION_ROUND_FLOOR", "floor"},
			{VIPS_OPERATION_ROUND_LAST, "VIPS_OPERATION_ROUND_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationRound", values );
	}

	return( etype );
}
GType
vips_operation_relational_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_RELATIONAL_EQUAL, "VIPS_OPERATION_RELATIONAL_EQUAL", "equal"},
			{VIPS_OPERATION_RELATIONAL_NOTEQUAL, "VIPS_OPERATION_RELATIONAL_NOTEQUAL", "notequal"},
			{VIPS_OPERATION_RELATIONAL_LESS, "VIPS_OPERATION_RELATIONAL_LESS", "less"},
			{VIPS_OPERATION_RELATIONAL_LESSEQ, "VIPS_OPERATION_RELATIONAL_LESSEQ", "lesseq"},
			{VIPS_OPERATION_RELATIONAL_MORE, "VIPS_OPERATION_RELATIONAL_MORE", "more"},
			{VIPS_OPERATION_RELATIONAL_MOREEQ, "VIPS_OPERATION_RELATIONAL_MOREEQ", "moreeq"},
			{VIPS_OPERATION_RELATIONAL_LAST, "VIPS_OPERATION_RELATIONAL_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationRelational", values );
	}

	return( etype );
}
GType
vips_operation_boolean_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_BOOLEAN_AND, "VIPS_OPERATION_BOOLEAN_AND", "and"},
			{VIPS_OPERATION_BOOLEAN_OR, "VIPS_OPERATION_BOOLEAN_OR", "or"},
			{VIPS_OPERATION_BOOLEAN_EOR, "VIPS_OPERATION_BOOLEAN_EOR", "eor"},
			{VIPS_OPERATION_BOOLEAN_LSHIFT, "VIPS_OPERATION_BOOLEAN_LSHIFT", "lshift"},
			{VIPS_OPERATION_BOOLEAN_RSHIFT, "VIPS_OPERATION_BOOLEAN_RSHIFT", "rshift"},
			{VIPS_OPERATION_BOOLEAN_LAST, "VIPS_OPERATION_BOOLEAN_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationBoolean", values );
	}

	return( etype );
}
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
vips_image_type_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_IMAGE_NONE, "VIPS_IMAGE_NONE", "none"},
			{VIPS_IMAGE_SETBUF, "VIPS_IMAGE_SETBUF", "setbuf"},
			{VIPS_IMAGE_SETBUF_FOREIGN, "VIPS_IMAGE_SETBUF_FOREIGN", "setbuf-foreign"},
			{VIPS_IMAGE_OPENIN, "VIPS_IMAGE_OPENIN", "openin"},
			{VIPS_IMAGE_MMAPIN, "VIPS_IMAGE_MMAPIN", "mmapin"},
			{VIPS_IMAGE_MMAPINRW, "VIPS_IMAGE_MMAPINRW", "mmapinrw"},
			{VIPS_IMAGE_OPENOUT, "VIPS_IMAGE_OPENOUT", "openout"},
			{VIPS_IMAGE_PARTIAL, "VIPS_IMAGE_PARTIAL", "partial"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsImageType", values );
	}

	return( etype );
}
GType
vips_interpretation_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_INTERPRETATION_MULTIBAND, "VIPS_INTERPRETATION_MULTIBAND", "multiband"},
			{VIPS_INTERPRETATION_B_W, "VIPS_INTERPRETATION_B_W", "b-w"},
			{VIPS_INTERPRETATION_HISTOGRAM, "VIPS_INTERPRETATION_HISTOGRAM", "histogram"},
			{VIPS_INTERPRETATION_FOURIER, "VIPS_INTERPRETATION_FOURIER", "fourier"},
			{VIPS_INTERPRETATION_XYZ, "VIPS_INTERPRETATION_XYZ", "xyz"},
			{VIPS_INTERPRETATION_LAB, "VIPS_INTERPRETATION_LAB", "lab"},
			{VIPS_INTERPRETATION_CMYK, "VIPS_INTERPRETATION_CMYK", "cmyk"},
			{VIPS_INTERPRETATION_LABQ, "VIPS_INTERPRETATION_LABQ", "labq"},
			{VIPS_INTERPRETATION_RGB, "VIPS_INTERPRETATION_RGB", "rgb"},
			{VIPS_INTERPRETATION_UCS, "VIPS_INTERPRETATION_UCS", "ucs"},
			{VIPS_INTERPRETATION_LCH, "VIPS_INTERPRETATION_LCH", "lch"},
			{VIPS_INTERPRETATION_LABS, "VIPS_INTERPRETATION_LABS", "labs"},
			{VIPS_INTERPRETATION_sRGB, "VIPS_INTERPRETATION_sRGB", "srgb"},
			{VIPS_INTERPRETATION_YXY, "VIPS_INTERPRETATION_YXY", "yxy"},
			{VIPS_INTERPRETATION_RGB16, "VIPS_INTERPRETATION_RGB16", "rgb16"},
			{VIPS_INTERPRETATION_GREY16, "VIPS_INTERPRETATION_GREY16", "grey16"},
			{VIPS_INTERPRETATION_ARRAY, "VIPS_INTERPRETATION_ARRAY", "array"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsInterpretation", values );
	}

	return( etype );
}
GType
vips_band_format_get_type( void )
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
		
		etype = g_enum_register_static( "VipsBandFormat", values );
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
vips_argument_flags_get_type( void )
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
		
		etype = g_enum_register_static( "VipsArgumentFlags", values );
	}

	return( etype );
}

/* Generated data ends here */

