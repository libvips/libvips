
/* Generated data (by glib-mkenums) */

/* auto-generated enums for vips introspection */

#include <vips/vips.h>
/* enumerations from "../../libvips/include/vips/foreign.h" */
GType
vips_foreign_flags_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GFlagsValue values[] = {
			{VIPS_FOREIGN_NONE, "VIPS_FOREIGN_NONE", "none"},
			{VIPS_FOREIGN_PARTIAL, "VIPS_FOREIGN_PARTIAL", "partial"},
			{VIPS_FOREIGN_BIGENDIAN, "VIPS_FOREIGN_BIGENDIAN", "bigendian"},
			{VIPS_FOREIGN_SEQUENTIAL, "VIPS_FOREIGN_SEQUENTIAL", "sequential"},
			{VIPS_FOREIGN_ALL, "VIPS_FOREIGN_ALL", "all"},
			{0, NULL, NULL}
		};
		
		etype = g_flags_register_static( "VipsForeignFlags", values );
	}

	return( etype );
}
GType
vips_saveable_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_SAVEABLE_MONO, "VIPS_SAVEABLE_MONO", "mono"},
			{VIPS_SAVEABLE_RGB, "VIPS_SAVEABLE_RGB", "rgb"},
			{VIPS_SAVEABLE_RGBA, "VIPS_SAVEABLE_RGBA", "rgba"},
			{VIPS_SAVEABLE_RGB_CMYK, "VIPS_SAVEABLE_RGB_CMYK", "rgb-cmyk"},
			{VIPS_SAVEABLE_ANY, "VIPS_SAVEABLE_ANY", "any"},
			{VIPS_SAVEABLE_LAST, "VIPS_SAVEABLE_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsSaveable", values );
	}

	return( etype );
}
GType
vips_foreign_tiff_compression_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_FOREIGN_TIFF_COMPRESSION_NONE, "VIPS_FOREIGN_TIFF_COMPRESSION_NONE", "none"},
			{VIPS_FOREIGN_TIFF_COMPRESSION_JPEG, "VIPS_FOREIGN_TIFF_COMPRESSION_JPEG", "jpeg"},
			{VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE, "VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE", "deflate"},
			{VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS, "VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS", "packbits"},
			{VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4, "VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4", "ccittfax4"},
			{VIPS_FOREIGN_TIFF_COMPRESSION_LZW, "VIPS_FOREIGN_TIFF_COMPRESSION_LZW", "lzw"},
			{VIPS_FOREIGN_TIFF_COMPRESSION_LAST, "VIPS_FOREIGN_TIFF_COMPRESSION_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsForeignTiffCompression", values );
	}

	return( etype );
}
GType
vips_foreign_tiff_predictor_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_FOREIGN_TIFF_PREDICTOR_NONE, "VIPS_FOREIGN_TIFF_PREDICTOR_NONE", "none"},
			{VIPS_FOREIGN_TIFF_PREDICTOR_HORIZONTAL, "VIPS_FOREIGN_TIFF_PREDICTOR_HORIZONTAL", "horizontal"},
			{VIPS_FOREIGN_TIFF_PREDICTOR_FLOAT, "VIPS_FOREIGN_TIFF_PREDICTOR_FLOAT", "float"},
			{VIPS_FOREIGN_TIFF_PREDICTOR_LAST, "VIPS_FOREIGN_TIFF_PREDICTOR_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsForeignTiffPredictor", values );
	}

	return( etype );
}
GType
vips_foreign_tiff_resunit_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_FOREIGN_TIFF_RESUNIT_CM, "VIPS_FOREIGN_TIFF_RESUNIT_CM", "cm"},
			{VIPS_FOREIGN_TIFF_RESUNIT_INCH, "VIPS_FOREIGN_TIFF_RESUNIT_INCH", "inch"},
			{VIPS_FOREIGN_TIFF_RESUNIT_LAST, "VIPS_FOREIGN_TIFF_RESUNIT_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsForeignTiffResunit", values );
	}

	return( etype );
}
GType
vips_foreign_dz_layout_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_FOREIGN_DZ_LAYOUT_DZ, "VIPS_FOREIGN_DZ_LAYOUT_DZ", "dz"},
			{VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY, "VIPS_FOREIGN_DZ_LAYOUT_ZOOMIFY", "zoomify"},
			{VIPS_FOREIGN_DZ_LAYOUT_GOOGLE, "VIPS_FOREIGN_DZ_LAYOUT_GOOGLE", "google"},
			{VIPS_FOREIGN_DZ_LAYOUT_LAST, "VIPS_FOREIGN_DZ_LAYOUT_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsForeignDzLayout", values );
	}

	return( etype );
}
GType
vips_foreign_dz_depth_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_FOREIGN_DZ_DEPTH_1PIXEL, "VIPS_FOREIGN_DZ_DEPTH_1PIXEL", "1pixel"},
			{VIPS_FOREIGN_DZ_DEPTH_1TILE, "VIPS_FOREIGN_DZ_DEPTH_1TILE", "1tile"},
			{VIPS_FOREIGN_DZ_DEPTH_1, "VIPS_FOREIGN_DZ_DEPTH_1", "1"},
			{VIPS_FOREIGN_DZ_DEPTH_LAST, "VIPS_FOREIGN_DZ_DEPTH_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsForeignDzDepth", values );
	}

	return( etype );
}
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
			{VIPS_EXTEND_BACKGROUND, "VIPS_EXTEND_BACKGROUND", "background"},
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
GType
vips_angle45_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_ANGLE45_0, "VIPS_ANGLE45_0", "0"},
			{VIPS_ANGLE45_45, "VIPS_ANGLE45_45", "45"},
			{VIPS_ANGLE45_90, "VIPS_ANGLE45_90", "90"},
			{VIPS_ANGLE45_135, "VIPS_ANGLE45_135", "135"},
			{VIPS_ANGLE45_180, "VIPS_ANGLE45_180", "180"},
			{VIPS_ANGLE45_225, "VIPS_ANGLE45_225", "225"},
			{VIPS_ANGLE45_270, "VIPS_ANGLE45_270", "270"},
			{VIPS_ANGLE45_315, "VIPS_ANGLE45_315", "315"},
			{VIPS_ANGLE45_LAST, "VIPS_ANGLE45_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsAngle45", values );
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
			{VIPS_OPERATION_ROUND_RINT, "VIPS_OPERATION_ROUND_RINT", "rint"},
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
GType
vips_operation_complex_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_COMPLEX_POLAR, "VIPS_OPERATION_COMPLEX_POLAR", "polar"},
			{VIPS_OPERATION_COMPLEX_RECT, "VIPS_OPERATION_COMPLEX_RECT", "rect"},
			{VIPS_OPERATION_COMPLEX_CONJ, "VIPS_OPERATION_COMPLEX_CONJ", "conj"},
			{VIPS_OPERATION_COMPLEX_LAST, "VIPS_OPERATION_COMPLEX_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationComplex", values );
	}

	return( etype );
}
GType
vips_operation_complex2_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_COMPLEX2_CROSS_PHASE, "VIPS_OPERATION_COMPLEX2_CROSS_PHASE", "cross-phase"},
			{VIPS_OPERATION_COMPLEX2_LAST, "VIPS_OPERATION_COMPLEX2_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationComplex2", values );
	}

	return( etype );
}
GType
vips_operation_complexget_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_COMPLEXGET_REAL, "VIPS_OPERATION_COMPLEXGET_REAL", "real"},
			{VIPS_OPERATION_COMPLEXGET_IMAG, "VIPS_OPERATION_COMPLEXGET_IMAG", "imag"},
			{VIPS_OPERATION_COMPLEXGET_LAST, "VIPS_OPERATION_COMPLEXGET_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationComplexget", values );
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
			{VIPS_DEMAND_STYLE_ERROR, "VIPS_DEMAND_STYLE_ERROR", "error"},
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
			{VIPS_IMAGE_ERROR, "VIPS_IMAGE_ERROR", "error"},
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
			{VIPS_INTERPRETATION_ERROR, "VIPS_INTERPRETATION_ERROR", "error"},
			{VIPS_INTERPRETATION_MULTIBAND, "VIPS_INTERPRETATION_MULTIBAND", "multiband"},
			{VIPS_INTERPRETATION_B_W, "VIPS_INTERPRETATION_B_W", "b-w"},
			{VIPS_INTERPRETATION_HISTOGRAM, "VIPS_INTERPRETATION_HISTOGRAM", "histogram"},
			{VIPS_INTERPRETATION_XYZ, "VIPS_INTERPRETATION_XYZ", "xyz"},
			{VIPS_INTERPRETATION_LAB, "VIPS_INTERPRETATION_LAB", "lab"},
			{VIPS_INTERPRETATION_CMYK, "VIPS_INTERPRETATION_CMYK", "cmyk"},
			{VIPS_INTERPRETATION_LABQ, "VIPS_INTERPRETATION_LABQ", "labq"},
			{VIPS_INTERPRETATION_RGB, "VIPS_INTERPRETATION_RGB", "rgb"},
			{VIPS_INTERPRETATION_CMC, "VIPS_INTERPRETATION_CMC", "cmc"},
			{VIPS_INTERPRETATION_LCH, "VIPS_INTERPRETATION_LCH", "lch"},
			{VIPS_INTERPRETATION_LABS, "VIPS_INTERPRETATION_LABS", "labs"},
			{VIPS_INTERPRETATION_sRGB, "VIPS_INTERPRETATION_sRGB", "srgb"},
			{VIPS_INTERPRETATION_YXY, "VIPS_INTERPRETATION_YXY", "yxy"},
			{VIPS_INTERPRETATION_FOURIER, "VIPS_INTERPRETATION_FOURIER", "fourier"},
			{VIPS_INTERPRETATION_RGB16, "VIPS_INTERPRETATION_RGB16", "rgb16"},
			{VIPS_INTERPRETATION_GREY16, "VIPS_INTERPRETATION_GREY16", "grey16"},
			{VIPS_INTERPRETATION_MATRIX, "VIPS_INTERPRETATION_MATRIX", "matrix"},
			{VIPS_INTERPRETATION_scRGB, "VIPS_INTERPRETATION_scRGB", "scrgb"},
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
			{VIPS_CODING_ERROR, "VIPS_CODING_ERROR", "error"},
			{VIPS_CODING_NONE, "VIPS_CODING_NONE", "none"},
			{VIPS_CODING_LABQ, "VIPS_CODING_LABQ", "labq"},
			{VIPS_CODING_RAD, "VIPS_CODING_RAD", "rad"},
			{VIPS_CODING_LAST, "VIPS_CODING_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsCoding", values );
	}

	return( etype );
}
GType
vips_access_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_ACCESS_RANDOM, "VIPS_ACCESS_RANDOM", "random"},
			{VIPS_ACCESS_SEQUENTIAL, "VIPS_ACCESS_SEQUENTIAL", "sequential"},
			{VIPS_ACCESS_SEQUENTIAL_UNBUFFERED, "VIPS_ACCESS_SEQUENTIAL_UNBUFFERED", "sequential-unbuffered"},
			{VIPS_ACCESS_LAST, "VIPS_ACCESS_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsAccess", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/colour.h" */
GType
vips_intent_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_INTENT_PERCEPTUAL, "VIPS_INTENT_PERCEPTUAL", "perceptual"},
			{VIPS_INTENT_RELATIVE, "VIPS_INTENT_RELATIVE", "relative"},
			{VIPS_INTENT_SATURATION, "VIPS_INTENT_SATURATION", "saturation"},
			{VIPS_INTENT_ABSOLUTE, "VIPS_INTENT_ABSOLUTE", "absolute"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsIntent", values );
	}

	return( etype );
}
GType
vips_pcs_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_PCS_LAB, "VIPS_PCS_LAB", "lab"},
			{VIPS_PCS_XYZ, "VIPS_PCS_XYZ", "xyz"},
			{VIPS_PCS_LAST, "VIPS_PCS_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsPCS", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/operation.h" */
GType
vips_operation_flags_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GFlagsValue values[] = {
			{VIPS_OPERATION_NONE, "VIPS_OPERATION_NONE", "none"},
			{VIPS_OPERATION_SEQUENTIAL, "VIPS_OPERATION_SEQUENTIAL", "sequential"},
			{VIPS_OPERATION_SEQUENTIAL_UNBUFFERED, "VIPS_OPERATION_SEQUENTIAL_UNBUFFERED", "sequential-unbuffered"},
			{VIPS_OPERATION_NOCACHE, "VIPS_OPERATION_NOCACHE", "nocache"},
			{0, NULL, NULL}
		};
		
		etype = g_flags_register_static( "VipsOperationFlags", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/convolution.h" */
GType
vips_precision_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_PRECISION_INTEGER, "VIPS_PRECISION_INTEGER", "integer"},
			{VIPS_PRECISION_FLOAT, "VIPS_PRECISION_FLOAT", "float"},
			{VIPS_PRECISION_APPROXIMATE, "VIPS_PRECISION_APPROXIMATE", "approximate"},
			{VIPS_PRECISION_LAST, "VIPS_PRECISION_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsPrecision", values );
	}

	return( etype );
}
GType
vips_combine_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_COMBINE_MAX, "VIPS_COMBINE_MAX", "max"},
			{VIPS_COMBINE_SUM, "VIPS_COMBINE_SUM", "sum"},
			{VIPS_COMBINE_LAST, "VIPS_COMBINE_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsCombine", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/morphology.h" */
GType
vips_operation_morphology_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GEnumValue values[] = {
			{VIPS_OPERATION_MORPHOLOGY_ERODE, "VIPS_OPERATION_MORPHOLOGY_ERODE", "erode"},
			{VIPS_OPERATION_MORPHOLOGY_DILATE, "VIPS_OPERATION_MORPHOLOGY_DILATE", "dilate"},
			{VIPS_OPERATION_MORPHOLOGY_LAST, "VIPS_OPERATION_MORPHOLOGY_LAST", "last"},
			{0, NULL, NULL}
		};
		
		etype = g_enum_register_static( "VipsOperationMorphology", values );
	}

	return( etype );
}
/* enumerations from "../../libvips/include/vips/object.h" */
GType
vips_argument_flags_get_type( void )
{
	static GType etype = 0;

	if( etype == 0 ) {
		static const GFlagsValue values[] = {
			{VIPS_ARGUMENT_NONE, "VIPS_ARGUMENT_NONE", "none"},
			{VIPS_ARGUMENT_REQUIRED, "VIPS_ARGUMENT_REQUIRED", "required"},
			{VIPS_ARGUMENT_CONSTRUCT, "VIPS_ARGUMENT_CONSTRUCT", "construct"},
			{VIPS_ARGUMENT_SET_ONCE, "VIPS_ARGUMENT_SET_ONCE", "set-once"},
			{VIPS_ARGUMENT_SET_ALWAYS, "VIPS_ARGUMENT_SET_ALWAYS", "set-always"},
			{VIPS_ARGUMENT_INPUT, "VIPS_ARGUMENT_INPUT", "input"},
			{VIPS_ARGUMENT_OUTPUT, "VIPS_ARGUMENT_OUTPUT", "output"},
			{VIPS_ARGUMENT_DEPRECATED, "VIPS_ARGUMENT_DEPRECATED", "deprecated"},
			{0, NULL, NULL}
		};
		
		etype = g_flags_register_static( "VipsArgumentFlags", values );
	}

	return( etype );
}

/* Generated data ends here */

