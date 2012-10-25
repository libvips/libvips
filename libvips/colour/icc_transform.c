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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

/* This is slightly different in lcms2.
 */
#define SIG_LAB ((cmsColorSpaceSignature) icSigLabData)
#else /*HAVE_LCMS*/
#include <lcms.h>
#define SIG_LAB icSigLabData
#endif

#include <icc34.h>

#include <vips/vips.h>

#include "colour.h"

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
		case icSigRgbData:
			code->input_bands = 3;
			code->input_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;
			icc->in_icc_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				TYPE_RGB_16 : TYPE_RGB_8;
			break;

		case icSigCmykData:
			code->input_bands = 4;
			code->input_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				VIPS_FORMAT_USHORT : VIPS_FORMAT_UCHAR;
			icc->in_icc_format = 
				code->in->BandFmt == VIPS_FORMAT_USHORT ? 
				TYPE_CMYK_16 : TYPE_CMYK_8;
			break;

		case icSigLabData:
			code->input_bands = 3;
			code->input_format = VIPS_FORMAT_FLOAT;
			icc->in_icc_format = TYPE_Lab_16;
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
		case icSigRgbData:
			colour->interpretation = VIPS_INTERPRETATION_RGB;
			colour->format = VIPS_FORMAT_UCHAR;
			colour->bands = 3;
			icc->out_icc_format = 
				icc->depth == 16 ? 
				TYPE_RGB_16 : TYPE_RGB_8;
			break;

		case icSigCmykData:
			colour->interpretation = VIPS_INTERPRETATION_CMYK;
			colour->format = 
				icc->depth == 8 ? 
				VIPS_FORMAT_UCHAR : VIPS_FORMAT_USHORT;
			colour->bands = 4;
			icc->out_icc_format = 
				icc->depth == 16 ? 
				TYPE_CMYK_16 : TYPE_CMYK_8;
			break;

		case icSigLabData:
			colour->interpretation = VIPS_INTERPRETATION_LAB;
			colour->format = VIPS_FORMAT_FLOAT;
			colour->bands = 3;
			icc->out_icc_format = TYPE_Lab_16;
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
		cmsGetColorSpace( icc->in_profile ) == SIG_LAB &&
		cmsGetColorSpace( icc->out_profile ) == SIG_LAB ) {
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
			!import->input_profile_filename) &&
		vips_image_get_typeof( code->in, VIPS_META_ICC_NAME ) ) {
		void *data;
		size_t data_length;

		if( vips_image_get_blob( code->in, VIPS_META_ICC_NAME, 
			&data, &data_length ) ||
			!(icc->in_profile = cmsOpenProfileFromMem( 
				data, data_length )) ) {
			vips_error( class->nickname,
				"%s", _( "unable to load embedded profile" ) );
			return( -1 );
		}
	}
	else if( import->input_profile_filename ) {
		if( !(icc->in_profile = cmsOpenProfileFromFile(
			import->input_profile_filename, "r" )) ) {
			vips_error( class->nickname,
				_( "unable to open profile \"%s\"" ), 
				import->input_profile_filename );
			return( -1 );
		}
	}
	else {
		vips_error( class->nickname, "%s", _( "no input profile" ) ); 
		return( -1 );
	}

	vips_check_intent( class->nickname, 
		icc->in_profile, icc->intent, LCMS_USED_AS_INPUT );

#ifdef HAVE_LCMS2
{
	cmsCIExyY white;
	cmsWhitePointFromTemp( &white, 6500 );

	icc->out_profile = cmsCreateLab4Profile( &white );
}
#else
	icc->out_profile = cmsCreateLabProfile( NULL );
#endif

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

/* Process a buffer of data.
 */
static void
vips_icc_import_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsIcc *icc = (VipsIcc *) colour;

	VipsPel *p = (VipsPel *) in[0];
	float *q = (float *) out;

	/* Buffer of encoded 16-bit pixels we transform.
	 */
	guint16 encoded[3 * PIXEL_BUFFER_SIZE];

	while( width > 0 ) {
		const int chunk = VIPS_MIN( width, PIXEL_BUFFER_SIZE );

#ifdef HAVE_LCMS2
		cmsDoTransform( icc->trans, p, encoded, chunk );
#else
		g_mutex_lock( icc->lock );
		cmsDoTransform( icc->trans, p, encoded, chunk );
		g_mutex_unlock( icc->lock );
#endif

		decode_lab( encoded, q, chunk );

		p += chunk * VIPS_IMAGE_SIZEOF_PEL( colour->out );
		q += chunk * 3;
		width -= chunk;
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

/**
 * vips_icc_import:
 * @in: input image
 * @out: output image
 *
 * Optional arguments:
 *
 * @input_profile: get the input profile from here
 * @intent: transform with this intent
 * @embedded: use profile embedded in input image
 *
 * Import an image from device space to D65 LAB with an ICC profile. 
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

#ifdef HAVE_LCMS2
{
	cmsCIExyY white;
	cmsWhitePointFromTemp( &white, 6500 );

	icc->in_profile = cmsCreateLab4Profile( &white );
}
#else
	icc->in_profile = cmsCreateLabProfile( NULL );
#endif

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

/* Process a buffer of data.
 */
static void
vips_icc_export_line( VipsColour *colour, 
	VipsPel *out, VipsPel **in, int width )
{
	VipsIcc *icc = (VipsIcc *) colour;

	float *p = (float *) in[0];
	VipsPel *q = (VipsPel *) out;

	/* Buffer of encoded 16-bit pixels we transform.
	 */
	guint16 encoded[3 * PIXEL_BUFFER_SIZE];

	while( width > 0 ) {
		const int chunk = VIPS_MIN( width, PIXEL_BUFFER_SIZE );

		encode_lab( p, encoded, chunk );

#ifdef HAVE_LCMS2
		cmsDoTransform( icc->trans, encoded, q, chunk );
#else
		g_mutex_lock( icc->lock );
		cmsDoTransform( icc->trans, encoded, q, chunk );
		g_mutex_unlock( icc->lock );
#endif

		p += chunk * 3;
		q += chunk * VIPS_IMAGE_SIZEOF_PEL( colour->out );
		width -= chunk;
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

/**
 * vips_icc_export:
 * @in: input image
 * @out: output image
 *
 * Optional arguments:
 *
 * @intent: transform with this intent
 * @depth: depth of output image in bits
 * @output_profile: get the output profile from here
 *
 * Export an image from D65 LAB to device space with an ICC profile. 
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
			!transform->input_profile_filename) &&
		vips_image_get_typeof( code->in, VIPS_META_ICC_NAME ) ) {
		void *data;
		size_t data_length;

		if( vips_image_get_blob( code->in, VIPS_META_ICC_NAME, 
			&data, &data_length ) ||
			!(icc->in_profile = cmsOpenProfileFromMem( 
				data, data_length )) ) {
			vips_error( class->nickname,
				"%s", _( "unable to load embedded profile" ) );
			return( -1 );
		}
	}
	else if( transform->input_profile_filename ) {
		if( !(icc->in_profile = cmsOpenProfileFromFile(
			transform->input_profile_filename, "r" )) ) {
			vips_error( class->nickname,
				_( "unable to open profile \"%s\"" ), 
				transform->input_profile_filename );
			return( -1 );
		}
	}
	else {
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
 * vips_icc_transform:
 * @in: input image
 * @out: output image
 * @output_profile: get the output profile from here
 *
 * Optional arguments:
 *
 * @input_profile: get the input profile from here
 * @intent: transform with this intent
 * @depth: depth of output image in bits
 * @embedded: use profile embedded in input image
 *
 * Transform an image with a pair of ICC profiles. The input image is moved to
 * profile-connection space with the input profile and then to the output
 * space with the output profile.
 *
 * If @embedded is set, the input profile is taken from the input image
 * metadata, if present. If there is no embedded profile,
 * @input_profile_filename is used as a fall-back.
 *
 * If @embedded is not set, the input profile is taken from
 * @input_profile_filename. If @input_profile_filename is not supplied, the
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

/**
 * vips_icc_ac2rc:
 * @in: input image
 * @out: output image
 * @profile_filename: use this profile
 *
 * Transform an image from absolute to relative colorimetry using the
 * MediaWhitePoint stored in the ICC profile.
 *
 * See also: im_icc_transform(), im_icc_import().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_icc_ac2rc( VipsImage *in, VipsImage *out, const char *profile_filename )
{
	cmsHPROFILE profile;
	double X, Y, Z;

	double add[3];
	double mul[3];

	IMAGE *t[2];

	if( !(profile = cmsOpenProfileFromFile( profile_filename, "r" )) )
		return( -1 );

#ifdef HAVE_LCMS2
{
	cmsCIEXYZ *media;

	if( !(media = cmsReadTag( profile, cmsSigMediaWhitePointTag )) ) {
		im_error( "im_icc_ac2rc", "%s", _( "unable to get media "
			"white point" ) );
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
		im_error( "im_icc_ac2rc", "%s", _( "unable to get media "
			"white point" ) );
		return( -1 );
	}

	X = media.X;
	Y = media.Y;
	Z = media.Z;
}
#endif

	cmsCloseProfile( profile );

	add[0] = 0.0;
	add[1] = 0.0;
	add[2] = 0.0;

	mul[0] = VIPS_D50_X0 / (X * 100.0);
	mul[1] = VIPS_D50_Y0 / (Y * 100.0);
	mul[2] = VIPS_D50_Z0 / (Z * 100.0);

	/* Do IM_CODING_LABQ too.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t1 = im_open_local( out, "im_icc_ac2rc-1", "p" );

		if( !t1 || im_LabQ2Lab( in, t1 ) )
			return( -1 );

		in = t1;
	}

	/* Do IM_CODING_RAD.
	 */
	if( in->Coding == IM_CODING_RAD ) {
		IMAGE *t1 = im_open_local( out, "im_icc_export:1", "p" );

		if( !t1 || im_rad2float( in, t1 ) )
			return( -1 );

		in = t1;
	}

	if( im_open_local_array( out, t, 2, "im_icc_ac2rc-2", "p" ) ||
		im_Lab2XYZ_temp( in, t[0], IM_D50_X0, IM_D50_Y0, IM_D50_Z0 ) ||
		im_lintra_vec( 3, mul, t[0], add, t[1] ) || 
		im_XYZ2Lab_temp( t[1], out, IM_D50_X0, IM_D50_Y0, IM_D50_Z0 ) )
		return( -1 );

	return( 0 );
}

#else /*!HAVE_LCMS*/

#include <vips/vips.h>

int
vips_icc_present( void )
{
	return( 0 );
}

#endif /*HAVE_LCMS*/
