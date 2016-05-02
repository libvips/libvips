/* Transform images with little cms
 *
 * 26/4/02 JC
 * 26/8/05
 * 	- attach profiles and intents to output images
 * 	- added im_icc_import_embedded() to import with an embedded profile
 * 12/5/06
 * 	- lock around cmsDoTransform
 * 23/1/07
 * 	- set RGB16 on 16-bit RGB export
 * 6/4/09
 * 	- catch lcms error messages
 * 2/11/09
 * 	- gtkdoc
 * 	- small cleanups
 * 	- call attach_profile() before im_wrapone() so the profile will get
 * 	  written if we are wrinting to a file
 * 2/8/10
 * 	- add lcms2
 * 12/7/11
 * 	- import and export cast @in to an appropriate format for you
 * 25/9/12
 * 	- redo as a class
 * 14/5/13
 * 	- import and export would segv on very wide images
 * 12/11/13
 * 	- support XYZ as an alternative PCS
 * 10/9/14
 * 	- support GRAY as an input and output space
 * 29/9/14
 * 	- check input profiles for compatibility with the input image, thanks
 * 	  James
 * 26/6/15
 *	- better profile sanity checking for icc import
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */
 
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#if defined( HAVE_LCMS ) || defined( HAVE_LCMS2 )

#include <stdio.h>
#include <math.h>
#include <assert.h>

/* Has to be before VIPS to avoid nameclashes.
 */
#ifdef HAVE_LCMS2
#include <lcms2.h>
#else /*HAVE_LCMS*/
#include <lcms.h>

/* Use the lcms2 names.
 */
#define cmsSigRgbData icSigRgbData 
#define cmsSigLabData icSigLabData 
#define cmsSigCmykData icSigCmykData 
#define cmsSigXYZData icSigXYZData 
#endif

#include <vips/vips.h>

#include "pcolour.h"

/* Call lcms with up to this many pixels at once.
 */
#define PIXEL_BUFFER_SIZE (10000)

/* LCMS1 was missing some stuff.
 */
#ifdef HAVE_LCMS
typedef DWORD cmsUInt32Number;

/* This doesn't exist in lcms1, just set it to zero.
 */
#define cmsFLAGS_NOCACHE (0)
#endif

/**
 * VipsIntent:
 * @VIPS_INTENT_PERCEPTUAL: perceptual rendering intent
 * @VIPS_INTENT_RELATIVE: relative colorimetric rendering intent
 * @VIPS_INTENT_SATURATION: saturation rendering intent
 * @VIPS_INTENT_ABSOLUTE: absolute colorimetric rendering intent
 *
 * The rendering intent. #VIPS_INTENT_ABSOLUTE is best for
 * scientific work, #VIPS_INTENT_RELATIVE is usually best for 
 * accurate communication with other imaging libraries.
 */

/**
 * VipsPCS:
 * @VIPS_PCS_LAB: use CIELAB D65 as the Profile Connection Space
 * @VIPS_PCS_XYZ: use XYZ as the Profile Connection Space
 *
 * Pick a Profile Connection Space for vips_icc_import() and
 * vips_icc_export(). LAB is usually best, XYZ can be more convenient in some 
 * cases. 
 */

/**
 * vips_icc_present:
 *
 * VIPS can optionally be built without the ICC library. Use this function to
 * test for its availability. 
 *
 * Returns: non-zero if the ICC library is present.
 */
int
vips_icc_present( void )
{
	return( 1 );
}

#define VIPS_TYPE_ICC (vips_icc_get_type())
#define VIPS_ICC( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
		VIPS_TYPE_ICC, VipsIcc ))
#define VIPS_ICC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
		VIPS_TYPE_ICC, VipsIccClass))
#define VIPS_IS_ICC( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_ICC ))
#define VIPS_IS_ICC_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_ICC ))
#define VIPS_ICC_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
		VIPS_TYPE_ICC, VipsIccClass ))

typedef struct _VipsIcc {
	VipsColourCode parent_instance;

	VipsIntent intent;
	VipsPCS pcs;
	int depth;

	cmsHPROFILE in_profile;
	cmsHPROFILE out_profile;
	cmsUInt32Number in_icc_format;
	cmsUInt32Number out_icc_format;
	cmsHTRANSFORM trans;

	/* We need to single-thread calls to LCMS 1.
	 */
	GMutex *lock;

} VipsIcc;

typedef VipsColourCodeClass VipsIccClass;

G_DEFINE_ABSTRACT_TYPE( VipsIcc, vips_icc, VIPS_TYPE_COLOUR_CODE );

/* Error from lcms.
 */

#ifdef HAVE_LCMS2
static void
icc_error( cmsContext context, cmsUInt32Number code, const char *text )
{
	vips_error( "VipsIcc", "%s", text );
}
#else
static int 
icc_error( int code, const char *text )
{
	if( code == LCMS_ERRC_WARNING )
		vips_warn( "VipsIcc", "%s", text );
	else
		vips_error( "VipsIcc", "%s", text );

	return( 0 );
}
#endif

static void
vips_icc_dispose( GObject *gobject )
{
	VipsIcc *icc = (VipsIcc *) gobject;

	VIPS_FREEF( cmsDeleteTransform, icc->trans );
	VIPS_FREEF( cmsCloseProfile, icc->in_profile );
	VIPS_FREEF( cmsCloseProfile, icc->out_profile );
	VIPS_FREEF( vips_g_mutex_free, icc->lock );

	G_OBJECT_CLASS( vips_icc_parent_class )->dispose( gobject );
}

/* Is a profile just a pcs stub.
 */
static gboolean
is_pcs( cmsHPROFILE profile )
{
	return( cmsGetColorSpace( profile ) == cmsSigLabData ||
		cmsGetColorSpace( profile ) == cmsSigXYZData ); 
}

static int
vips_icc_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;

	if( icc->depth != 8 &&
		icc->depth != 16 ) {
		vips_error( class->nickname, 
			"%s", _( "depth must be 8 or 16" ) );
		return( -1 );
	}

	if( icc->in_profile &&
		code->in ) {
		switch( cmsGetColorSpace( icc->in_profile ) ) {
		case cmsSigRgbData:
			colour->input_bands = 3;
			code->input_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;
			icc->in_icc_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				TYPE_RGB_16 : TYPE_RGB_8;
			break;

#ifdef HAVE_LCMS2
		case cmsSigGrayData:
			colour->input_bands = 1;
			code->input_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;
			icc->in_icc_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				TYPE_GRAY_16 : TYPE_GRAY_8;
			break;
#endif /*HAVE_LCMS2*/

		case cmsSigCmykData:
			colour->input_bands = 4;
			code->input_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;
			icc->in_icc_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				TYPE_CMYK_16 : TYPE_CMYK_8;
			break;

		case cmsSigLabData:
			colour->input_bands = 3;
			code->input_format = VIPS_FORMAT_FLOAT;
			code->input_interpretation = 
				VIPS_INTERPRETATION_LAB;
			icc->in_icc_format = TYPE_Lab_16;
			break;

		case cmsSigXYZData:
			colour->input_bands = 3;
			code->input_format = VIPS_FORMAT_FLOAT;
			icc->in_icc_format = TYPE_XYZ_16;
			break;

		default:
			vips_error( class->nickname, 
				_( "unimplemented input color space 0x%x" ), 
				cmsGetColorSpace( icc->in_profile ) );
			return( -1 );
		}
	}

	if( icc->out_profile ) 
		switch( cmsGetColorSpace( icc->out_profile ) ) {
		case cmsSigRgbData:
			colour->interpretation = 
				icc->depth == 8 ? 
				VIPS_INTERPRETATION_RGB : 
					VIPS_INTERPRETATION_RGB16;
			colour->format = 
				icc->depth == 8 ? 
				VIPS_FORMAT_UCHAR : VIPS_FORMAT_USHORT;
			colour->bands = 3;
			icc->out_icc_format = 
				icc->depth == 16 ? 
				TYPE_RGB_16 : TYPE_RGB_8;
			break;

#ifdef HAVE_LCMS2
		case cmsSigGrayData:
			colour->interpretation = 
				icc->depth == 8 ? 
				VIPS_INTERPRETATION_B_W : 
					VIPS_INTERPRETATION_GREY16;
			colour->format = 
				icc->depth == 8 ? 
				VIPS_FORMAT_UCHAR : VIPS_FORMAT_USHORT;
			colour->bands = 1;
			icc->out_icc_format = 
				icc->depth == 16 ? 
				TYPE_GRAY_16 : TYPE_GRAY_8;
			break;
#endif /*HAVE_LCMS2*/

		case cmsSigCmykData:
			colour->interpretation = VIPS_INTERPRETATION_CMYK;
			colour->format = 
				icc->depth == 8 ? 
				VIPS_FORMAT_UCHAR : VIPS_FORMAT_USHORT;
			colour->bands = 4;
			icc->out_icc_format = 
				icc->depth == 16 ? 
				TYPE_CMYK_16 : TYPE_CMYK_8;
			break;

		case cmsSigLabData:
			colour->interpretation = VIPS_INTERPRETATION_LAB;
			colour->format = VIPS_FORMAT_FLOAT;
			colour->bands = 3;
			icc->out_icc_format = TYPE_Lab_16;
			break;

		case cmsSigXYZData:
			colour->interpretation = VIPS_INTERPRETATION_XYZ;
			colour->format = VIPS_FORMAT_FLOAT;
			colour->bands = 3;
			icc->out_icc_format = TYPE_XYZ_16;
			break;

		default:
			vips_error( class->nickname, 
				_( "unimplemented output color space 0x%x" ), 
				cmsGetColorSpace( icc->out_profile ) );
			return( -1 );
		}

	/* At least one must be a device profile.
	 */
	if( icc->in_profile &&
		icc->out_profile &&
		is_pcs( icc->in_profile ) &&
		is_pcs( icc->out_profile ) ) { 
		vips_error( class->nickname,
			"%s", _( "no device profile" ) ); 
		return( -1 );
	}

	/* Use cmsFLAGS_NOCACHE to disable the 1-pixel cache and make
	 * calling cmsDoTransform() from multiple threads safe.
	 */
	if( !(icc->trans = cmsCreateTransform( 
		icc->in_profile, icc->in_icc_format,
		icc->out_profile, icc->out_icc_format, 
		icc->intent, cmsFLAGS_NOCACHE )) )
		return( -1 );

	if( VIPS_OBJECT_CLASS( vips_icc_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

static void
vips_icc_class_init( VipsIccClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->dispose = vips_icc_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc";
	object_class->description = _( "transform using ICC profiles" );
	object_class->build = vips_icc_build;

	VIPS_ARG_ENUM( class, "intent", 6, 
		_( "Intent" ), 
		_( "Rendering intent" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsIcc, intent ),
		VIPS_TYPE_INTENT, VIPS_INTENT_RELATIVE );

	VIPS_ARG_ENUM( class, "pcs", 6, 
		_( "PCS" ), 
		_( "Set Profile Connection Space" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsIcc, pcs ),
		VIPS_TYPE_PCS, VIPS_PCS_LAB );

#ifdef HAVE_LCMS2
	cmsSetLogErrorHandler( icc_error );
#else
	/* Ask lcms not to abort on error.
	 */
	cmsErrorAction( LCMS_ERROR_IGNORE );
	cmsSetErrorHandler( icc_error );
#endif

}

static void
vips_icc_init( VipsIcc *icc )
{
	icc->lock = vips_g_mutex_new();
	icc->intent = VIPS_INTENT_RELATIVE;
	icc->pcs = VIPS_PCS_LAB;
	icc->depth = 8;
}

typedef struct _VipsIccImport {
	VipsIcc parent_instance;

	gboolean embedded;
	char *input_profile_filename;

} VipsIccImport;

typedef VipsIccClass VipsIccImportClass;

G_DEFINE_TYPE( VipsIccImport, vips_icc_import, VIPS_TYPE_ICC );

static void
vips_check_intent( const char *domain, 
	cmsHPROFILE profile, VipsIntent intent, int direction )
{
	if( profile &&
		!cmsIsIntentSupported( profile, intent, direction ) )
		vips_warn( domain,
			_( "intent %d (%s) not supported by "
			"%s profile; falling back to default intent" ), 
			intent, vips_enum_nick( VIPS_TYPE_INTENT, intent ),
			direction == LCMS_USED_AS_INPUT ?
				_( "input" ) : _( "output" ) );
}

static int
vips_icc_profile_needs_bands( cmsHPROFILE profile )
{
	int needs_bands;

	switch( cmsGetColorSpace( profile ) ) {
#ifdef HAVE_LCMS2
	case cmsSigGrayData:
		needs_bands = 1;
		break;
#endif /*HAVE_LCMS2*/

	case cmsSigRgbData:
	case cmsSigLabData:
	case cmsSigXYZData:
		needs_bands = 3;
		break;

	case cmsSigCmykData:
		needs_bands = 4;
		break;

	default:
		needs_bands = -1;
		break;
	}

	return( needs_bands );
}

/* How many bands we expect to see from an image after preprocessing by our
 * parent classes. This is a bit fragile :-( 
 *
 * FIXME ... split the _build() for colour into separate preprocess / process
 * / postprocess phases so we can load profiles after preprocess but before
 * actual processing takes place.
 */
static int
vips_image_expected_bands( VipsImage *image )
{
	int expected_bands;

	switch( image->Type ) { 
	case VIPS_INTERPRETATION_B_W:
	case VIPS_INTERPRETATION_GREY16:
		expected_bands = 1;
		break;

	case VIPS_INTERPRETATION_XYZ:
	case VIPS_INTERPRETATION_LAB:
	case VIPS_INTERPRETATION_LABQ:
	case VIPS_INTERPRETATION_RGB:
	case VIPS_INTERPRETATION_CMC:
	case VIPS_INTERPRETATION_LCH:
	case VIPS_INTERPRETATION_LABS:
	case VIPS_INTERPRETATION_sRGB:
	case VIPS_INTERPRETATION_YXY:
	case VIPS_INTERPRETATION_RGB16:
	case VIPS_INTERPRETATION_scRGB:
	case VIPS_INTERPRETATION_HSV:
		expected_bands = 3;
		break;

	case VIPS_INTERPRETATION_CMYK:
		expected_bands = 4;
		break;

	case VIPS_INTERPRETATION_MULTIBAND:
	case VIPS_INTERPRETATION_HISTOGRAM:
	case VIPS_INTERPRETATION_MATRIX:
	case VIPS_INTERPRETATION_FOURIER:
	default:
		expected_bands = image->Bands;
		break;
	}

	expected_bands = VIPS_MIN( expected_bands, image->Bands );

	return( expected_bands );
}

static cmsHPROFILE
vips_icc_load_profile_image( const char *domain, VipsImage *image )
{
	void *data;
	size_t data_length;
	cmsHPROFILE profile;

	if( !vips_image_get_typeof( image, VIPS_META_ICC_NAME ) )
		return( NULL ); 

	if( vips_image_get_blob( image, VIPS_META_ICC_NAME, 
		&data, &data_length ) ||
		!(profile = cmsOpenProfileFromMem( data, data_length )) ) {
		vips_warn( domain, "%s", _( "corrupt embedded profile" ) );
		return( NULL ); 
	}

	if( vips_image_expected_bands( image ) != 
		vips_icc_profile_needs_bands( profile ) ) {
		VIPS_FREEF( cmsCloseProfile, profile );
		vips_warn( domain, 
			"%s", _( "embedded profile incompatible with image" ) );
		return( NULL );
	}

	return( profile );
}

static cmsHPROFILE
vips_icc_load_profile_file( const char *domain, 
	VipsImage *image, const char *filename )
{
	cmsHPROFILE profile;

	if( !(profile = cmsOpenProfileFromFile( filename, "r" )) ) {
		vips_error( domain, 
			_( "unable to open profile \"%s\"" ), filename );
		return( NULL );
	}

	if( vips_image_expected_bands( image ) != 
		vips_icc_profile_needs_bands( profile ) ) {
		VIPS_FREEF( cmsCloseProfile, profile );
		vips_warn( domain, 
			_( "profile \"%s\" incompatible with image" ),
			filename );
		return( NULL );
	}

	return( profile );
}

static int
vips_icc_import_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;
	VipsIccImport *import = (VipsIccImport *) object;

	/* We read the input profile like this:
	 *
	 *	embedded	filename	action
	 *	0		0 		image
	 *	1		0		image
	 *	0		1		file
	 *	1		1		image, then fall back to file
	 *	
	 * see also import_build.
	 */

	if( code->in &&
		(import->embedded ||
			!import->input_profile_filename) )
		icc->in_profile = vips_icc_load_profile_image( class->nickname,
			code->in );

	if( !icc->in_profile &&
		code->in &&
		import->input_profile_filename ) 
		icc->in_profile = vips_icc_load_profile_file( class->nickname,
			code->in, import->input_profile_filename );

	if( !icc->in_profile ) {
		vips_error( class->nickname, "%s", _( "no input profile" ) ); 
		return( -1 );
	}

	vips_check_intent( class->nickname, 
		icc->in_profile, icc->intent, LCMS_USED_AS_INPUT );

	if( icc->pcs == VIPS_PCS_LAB ) { 
#ifdef HAVE_LCMS2
		cmsCIExyY white;
		cmsWhitePointFromTemp( &white, 6500 );

		icc->out_profile = cmsCreateLab4Profile( &white );
#else
		icc->out_profile = cmsCreateLabProfile( NULL );
#endif
	}
	else 
		icc->out_profile = cmsCreateXYZProfile();

	if( VIPS_OBJECT_CLASS( vips_icc_import_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

static void 
decode_lab( guint16 *fixed, float *lab, int n )
{
	int i;

        for( i = 0; i < n; i++ ) {
                lab[0] = (double) fixed[0] / 652.800;
                lab[1] = ((double) fixed[1] / 256.0) - 128.0;
                lab[2] = ((double) fixed[2] / 256.0) - 128.0;

                lab += 3;
                fixed += 3;
        }
}

#define X_FAC (VIPS_D50_X0 * 32768 / (VIPS_D65_X0 * 100))
#define Y_FAC (VIPS_D50_Y0 * 32768 / (VIPS_D65_Y0 * 100))
#define Z_FAC (VIPS_D50_Z0 * 32768 / (VIPS_D65_Z0 * 100))

static void 
decode_xyz( guint16 *fixed, float *xyz, int n )
{
	int i;

        for( i = 0; i < n; i++ ) {
                xyz[0] = (double) fixed[0] / X_FAC;
                xyz[1] = (double) fixed[1] / Y_FAC;
                xyz[2] = (double) fixed[2] / Z_FAC;

                xyz += 3;
                fixed += 3;
        }
}

/* Process a buffer of data.
 */
static void
vips_icc_import_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsIcc *icc = (VipsIcc *) colour;

	VipsPel *p;
	float *q;
	int i;

	/* Buffer of encoded 16-bit pixels we transform.
	 */
	guint16 encoded[3 * PIXEL_BUFFER_SIZE];

	p = (VipsPel *) in[0];
	q = (float *) out;
	for( i = 0; i < width; i += PIXEL_BUFFER_SIZE ) {
		const int chunk = VIPS_MIN( width - i, PIXEL_BUFFER_SIZE );

#ifdef HAVE_LCMS2
		cmsDoTransform( icc->trans, p, encoded, chunk );
#else
		g_mutex_lock( icc->lock );
		cmsDoTransform( icc->trans, p, encoded, chunk );
		g_mutex_unlock( icc->lock );
#endif

		if( icc->pcs == VIPS_PCS_LAB ) 
			decode_lab( encoded, q, chunk );
		else
			decode_xyz( encoded, q, chunk );

		p += PIXEL_BUFFER_SIZE * VIPS_IMAGE_SIZEOF_PEL( colour->in[0] );
		q += PIXEL_BUFFER_SIZE * 3;
	}
}

static void
vips_icc_import_class_init( VipsIccImportClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc_import";
	object_class->description = _( "import from device with ICC profile" );
	object_class->build = vips_icc_import_build;

	colour_class->process_line = vips_icc_import_line;

	VIPS_ARG_BOOL( class, "embedded", 110, 
		_( "Embedded" ),
		_( "Use embedded input profile, if available" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIccImport, embedded ),
		FALSE );

	VIPS_ARG_STRING( class, "input_profile", 120, 
		_( "Input profile" ),
		_( "Filename to load input profile from" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIccImport, input_profile_filename ),
		NULL );

}

static void
vips_icc_import_init( VipsIccImport *import )
{
}

typedef struct _VipsIccExport {
	VipsIcc parent_instance;

	char *output_profile_filename;

} VipsIccExport;

typedef VipsIccClass VipsIccExportClass;

G_DEFINE_TYPE( VipsIccExport, vips_icc_export, VIPS_TYPE_ICC );

static int
vips_icc_export_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;
	VipsIccExport *export = (VipsIccExport *) object;

	/* If icc->pcs hasn't been set and this image is tagged as XYZ, swap
	 * to XYZ pcs. This will save a XYZ->LAB conversion when we chain up.
	 */
	if( !vips_object_argument_isset( object, "pcs" ) &&
		code->in &&
		code->in->Type == VIPS_INTERPRETATION_XYZ )  
		icc->pcs = VIPS_PCS_XYZ; 

	if( icc->pcs == VIPS_PCS_LAB ) { 
#ifdef HAVE_LCMS2
		cmsCIExyY white;
		cmsWhitePointFromTemp( &white, 6500 );

		icc->in_profile = cmsCreateLab4Profile( &white );
#else
		icc->in_profile = cmsCreateLabProfile( NULL );
#endif
	}
	else 
		icc->in_profile = cmsCreateXYZProfile();

	if( code->in &&
		!export->output_profile_filename &&
		vips_image_get_typeof( code->in, VIPS_META_ICC_NAME ) ) {
		void *data;
		size_t data_length;

		if( vips_image_get_blob( code->in, VIPS_META_ICC_NAME, 
			&data, &data_length ) ||
			!(icc->out_profile = cmsOpenProfileFromMem( 
				data, data_length )) ) {
			vips_error( class->nickname,
				"%s", _( "unable to load embedded profile" ) );
			return( -1 );
		}
	}
	else if( export->output_profile_filename ) {
		if( !(icc->out_profile = cmsOpenProfileFromFile(
			export->output_profile_filename, "r" )) ) {
			vips_error( class->nickname,
				_( "unable to open profile \"%s\"" ), 
				export->output_profile_filename );
			return( -1 );
		}

		colour->profile_filename = export->output_profile_filename;
	}
	else {
		vips_error( class->nickname, "%s", _( "no output profile" ) ); 
		return( -1 );
	}

	vips_check_intent( class->nickname, 
		icc->out_profile, icc->intent, LCMS_USED_AS_OUTPUT );

	if( VIPS_OBJECT_CLASS( vips_icc_export_parent_class )->build( object ) )
		return( -1 );

	return( 0 );
}

/* Pack a buffer of floats into lcms's fixed-point formats. Cut from
 * lcms-1.0.8.
 */
static void 
encode_lab( float *lab, guint16 *fixed, int n )
{
	int i;

	for( i = 0; i < n; i++ ) {
		float L = lab[0];
		float a = lab[1];
		float b = lab[2];

		if( L < 0 ) 
			L = 0;
		if( L > 100. ) 
			L = 100.;

		if( a < -128. ) 
			a = -128;
		if( a > 127.9961 ) 
			a = 127.9961;
		if( b < -128. ) 
			b = -128;
		if( b > 127.9961 ) 
			b = 127.9961;

		fixed[0] = L *  652.800 + 0.5;
		fixed[1] = (a + 128.0) * 256.0 + 0.5;
		fixed[2] = (b + 128.0) * 256.0 + 0.5;

		lab += 3;
		fixed += 3;
	}
}

#define MAX_ENCODEABLE_XYZ  (100 * (1.0 + 32767.0 / 32768.0))

// 1.15 fixed point for XYZ

static void 
encode_xyz( float *xyz, guint16 *fixed, int n )
{
	int i;

	for( i = 0; i < n; i++ ) {
		float X = xyz[0];
		float Y = xyz[1];
		float Z = xyz[2];

		if( X < 0 ) 
			X = 0;
		if( X > MAX_ENCODEABLE_XYZ ) 
			X = MAX_ENCODEABLE_XYZ;

		if( Y < 0 ) 
			Y = 0;
		if( Y > MAX_ENCODEABLE_XYZ ) 
			Y = MAX_ENCODEABLE_XYZ;

		if( Z < 0 ) 
			Z = 0;
		if( Z > MAX_ENCODEABLE_XYZ ) 
			Z = MAX_ENCODEABLE_XYZ;

		fixed[0] = X * X_FAC + 0.5;
		fixed[1] = Y * Y_FAC + 0.5;
		fixed[2] = Z * Z_FAC + 0.5;

		xyz += 3;
		fixed += 3;
	}
}

/* Process a buffer of data.
 */
static void
vips_icc_export_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsIcc *icc = (VipsIcc *) colour;

	float *p;
	VipsPel *q;
	int x;

	/* Buffer of encoded 16-bit pixels we transform.
	 */
	guint16 encoded[3 * PIXEL_BUFFER_SIZE];

	p = (float *) in[0];
	q = (VipsPel *) out;
	for( x = 0; x < width; x += PIXEL_BUFFER_SIZE ) {
		const int chunk = VIPS_MIN( width - x, PIXEL_BUFFER_SIZE );

		if( icc->pcs == VIPS_PCS_LAB )
			encode_lab( p, encoded, chunk );
		else
			encode_xyz( p, encoded, chunk );

#ifdef HAVE_LCMS2
		cmsDoTransform( icc->trans, encoded, q, chunk );
#else
		g_mutex_lock( icc->lock );
		cmsDoTransform( icc->trans, encoded, q, chunk );
		g_mutex_unlock( icc->lock );
#endif

		p += PIXEL_BUFFER_SIZE * 3;
		q += PIXEL_BUFFER_SIZE * VIPS_IMAGE_SIZEOF_PEL( colour->out );
	}
}

static void
vips_icc_export_class_init( VipsIccExportClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc_export";
	object_class->description = _( "output to device with ICC profile" );
	object_class->build = vips_icc_export_build;

	colour_class->process_line = vips_icc_export_line;

	VIPS_ARG_STRING( class, "output_profile", 110, 
		_( "Output profile" ),
		_( "Filename to load output profile from" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIccExport, output_profile_filename ),
		NULL );

	VIPS_ARG_INT( class, "depth", 130, 
		_( "Depth" ),
		_( "Output device space depth in bits" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIcc, depth ),
		8, 16, 8 );
}

static void
vips_icc_export_init( VipsIccExport *export )
{
}

typedef struct _VipsIccTransform {
	VipsIcc parent_instance;

	gboolean embedded;
	char *input_profile_filename;
	char *output_profile_filename;

} VipsIccTransform;

typedef VipsIccClass VipsIccTransformClass;

G_DEFINE_TYPE( VipsIccTransform, vips_icc_transform, VIPS_TYPE_ICC );

static int
vips_icc_transform_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object ); 
	VipsColour *colour = (VipsColour *) object;
	VipsColourCode *code = (VipsColourCode *) object;
	VipsIcc *icc = (VipsIcc *) object;
	VipsIccTransform *transform = (VipsIccTransform *) object;

	/* We read the input profile like this:
	 *
	 *	embedded	filename	action
	 *	0		0 		image
	 *	1		0		image
	 *	0		1		file
	 *	1		1		image, then fall back to file
	 *	
	 * see also import_build.
	 */

	if( code->in &&
		(transform->embedded ||
			!transform->input_profile_filename) )
		icc->in_profile = vips_icc_load_profile_image( class->nickname,
			code->in );

	if( !icc->in_profile &&
		code->in &&
		transform->input_profile_filename ) 
		icc->in_profile = vips_icc_load_profile_file( class->nickname,
			code->in, transform->input_profile_filename );

	if( !icc->in_profile ) {
		vips_error( class->nickname, "%s", _( "no input profile" ) ); 
		return( -1 );
	}

	if( transform->output_profile_filename ) {
		if( !(icc->out_profile = cmsOpenProfileFromFile(
			transform->output_profile_filename, "r" )) ) {
			vips_error( class->nickname,
				_( "unable to open profile \"%s\"" ), 
				transform->output_profile_filename );
			return( -1 );
		}

		colour->profile_filename = transform->output_profile_filename;
	}

	vips_check_intent( class->nickname, 
		icc->in_profile, icc->intent, LCMS_USED_AS_INPUT );
	vips_check_intent( class->nickname, 
		icc->out_profile, icc->intent, LCMS_USED_AS_OUTPUT );

	if( VIPS_OBJECT_CLASS( vips_icc_transform_parent_class )->
		build( object ) )
		return( -1 );

	return( 0 );
}

/* Process a buffer of data.
 */
static void
vips_icc_transform_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsIcc *icc = (VipsIcc *) colour;

#ifdef HAVE_LCMS2
	cmsDoTransform( icc->trans, in[0], out, width );
#else
	g_mutex_lock( icc->lock );
	cmsDoTransform( icc->trans, in[0], out, width );
	g_mutex_unlock( icc->lock );
#endif
}

static void
vips_icc_transform_class_init( VipsIccImportClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "icc_transform";
	object_class->description = 
		_( "transform between devices with ICC profiles" );
	object_class->build = vips_icc_transform_build;

	colour_class->process_line = vips_icc_transform_line;

	VIPS_ARG_STRING( class, "output_profile", 110, 
		_( "Output profile" ),
		_( "Filename to load output profile from" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsIccTransform, output_profile_filename ),
		NULL );

	VIPS_ARG_BOOL( class, "embedded", 120, 
		_( "Embedded" ),
		_( "Use embedded input profile, if available" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIccTransform, embedded ),
		FALSE );

	VIPS_ARG_STRING( class, "input_profile", 130, 
		_( "Input profile" ),
		_( "Filename to load input profile from" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIccTransform, input_profile_filename ),
		NULL );

	VIPS_ARG_INT( class, "depth", 140, 
		_( "Depth" ),
		_( "Output device space depth in bits" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT, 
		G_STRUCT_OFFSET( VipsIcc, depth ),
		8, 16, 8 );

}

static void
vips_icc_transform_init( VipsIccTransform *transform )
{
}

/**
 * vips_icc_ac2rc:
 * @in: input image
 * @out: output image
 * @profile_filename: use this profile
 *
 * Transform an image from absolute to relative colorimetry using the
 * MediaWhitePoint stored in the ICC profile.
 *
 * See also: vips_icc_transform(), vips_icc_import().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_ac2rc( VipsImage *in, VipsImage **out, const char *profile_filename )
{
	VipsImage *t;
	cmsHPROFILE profile;
	double X, Y, Z;
	double *add;
	double *mul;
	int i;

	if( !(profile = cmsOpenProfileFromFile( profile_filename, "r" )) )
		return( -1 );

#ifdef HAVE_LCMS2
{
	cmsCIEXYZ *media;

	if( !(media = cmsReadTag( profile, cmsSigMediaWhitePointTag )) ) {
		vips_error( "vips_icc_ac2rc", 
			"%s", _( "unable to get media white point" ) );
		return( -1 );
	}

	X = media->X;
	Y = media->Y;
	Z = media->Z;
}
#else /*HAVE_LCMS*/
{
	cmsCIEXYZ media;

	if( !cmsTakeMediaWhitePoint( &media, profile ) ) {
		vips_error( "vips_icc_ac2rc", 
			"%s", _( "unable to get media white point" ) );
		return( -1 );
	}

	X = media.X;
	Y = media.Y;
	Z = media.Z;
}
#endif

	cmsCloseProfile( profile );

	/* We need XYZ so we can adjust the white balance.
	 */
	if( vips_colourspace( in, &t, VIPS_INTERPRETATION_XYZ, NULL ) )
		return( -1 );
	in = t;

	if( !(add = VIPS_ARRAY( in, in->Bands, double )) ||
		!(mul = VIPS_ARRAY( in, in->Bands, double )) )
		return( -1 );

	/* There might be extra bands off to the right somewhere.
	 */
	for( i = 0; i < in->Bands; i++ ) 
		add[i] = 0.0;

	mul[0] = VIPS_D50_X0 / (X * 100.0);
	mul[1] = VIPS_D50_Y0 / (Y * 100.0);
	mul[2] = VIPS_D50_Z0 / (Z * 100.0);

	for( i = 3; i < in->Bands; i++ ) 
		mul[i] = 1.0;

	if( vips_linear( in, &t, add, mul, in->Bands, NULL ) ) {
		g_object_unref( in );
		return( -1 );
	}
	g_object_unref( in );
	in = t;

	*out = in;

	return( 0 );
}

#else /*!HAVE_LCMS*/

#include <vips/vips.h>

int
vips_icc_present( void )
{
	return( 0 );
}

int
vips_icc_ac2rc( VipsImage *in, VipsImage **out, const char *profile_filename )
{
	vips_error( "VipsIcc", "%s", 
		_( "libvips configured without lcms support" ) );

	return( -1 );
}

#endif /*HAVE_LCMS*/

/**
 * vips_icc_import:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @input_profile: get the input profile from here
 * * @intent: transform with this intent
 * * @embedded: use profile embedded in input image
 * * @pcs: use XYZ or LAB PCS
 *
 * Import an image from device space to D65 LAB with an ICC profile. If @pcs is
 * set to #VIPS_PCS_XYZ, use CIE XYZ PCS instead. 
 *
 * If @embedded is set, the input profile is taken from the input image
 * metadata. If there is no embedded profile,
 * @input_profile_filename is used as a fall-back.
 *
 * If @embedded is not set, the input profile is taken from
 * @input_profile. If @input_profile is not supplied, the
 * metadata profile, if any, is used as a fall-back. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_import( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "icc_import", ap, in, out );
	va_end( ap );

	return( result );
}

/**
 * vips_icc_export:
 * @in: input image
 * @out: output image
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @intent: transform with this intent
 * * @depth: depth of output image in bits
 * * @output_profile: get the output profile from here
 * * @pcs: use XYZ or LAB PCS
 *
 * Export an image from D65 LAB to device space with an ICC profile. 
 * If @pcs is
 * set to #VIPS_PCS_XYZ, use CIE XYZ PCS instead. 
 * If @output_profile is not set, use the embedded profile, if any. 
 * If @output_profile is set, export with that and attach it to the output 
 * image. 
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_export( VipsImage *in, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "icc_export", ap, in, out );
	va_end( ap );

	return( result );
}

/**
 * vips_icc_transform:
 * @in: input image
 * @out: output image
 * @output_profile: get the output profile from here
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @input_profile: get the input profile from here
 * * @intent: transform with this intent
 * * @depth: depth of output image in bits
 * * @embedded: use profile embedded in input image
 *
 * Transform an image with a pair of ICC profiles. The input image is moved to
 * profile-connection space with the input profile and then to the output
 * space with the output profile.
 *
 * If @embedded is set, the input profile is taken from the input image
 * metadata, if present. If there is no embedded profile,
 * @input_profile is used as a fall-back.
 *
 * If @embedded is not set, the input profile is taken from
 * @input_profile. If @input_profile is not supplied, the
 * metadata profile, if any, is used as a fall-back. 
 *
 * Use vips_icc_import() and vips_icc_export() to do either the first or 
 * second half of this operation in isolation.
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_icc_transform( VipsImage *in, VipsImage **out, 
	const char *output_profile, ... )
{
	va_list ap;
	int result;

	va_start( ap, output_profile );
	result = vips_call_split( "icc_transform", ap, 
		in, out, output_profile );
	va_end( ap );

	return( result );
}
