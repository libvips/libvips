/* save to nifti
 *
 * 5/7/18
 * 	- from fitssave.c
 * 9/9/19
 * 	- use double for all floating point scalar metadata, like other loaders
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

/*
#define DEBUG_VERBOSE
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef HAVE_NIFTI

#include <nifti1_io.h>

#include "pforeign.h"

typedef struct _VipsForeignSaveNifti {
	VipsForeignSave parent_object;

	/* Filename for save.
	 */
	char *filename; 

	nifti_image *nim;

} VipsForeignSaveNifti;

typedef VipsForeignSaveClass VipsForeignSaveNiftiClass;

G_DEFINE_TYPE( VipsForeignSaveNifti, vips_foreign_save_nifti, 
	VIPS_TYPE_FOREIGN_SAVE );

static void
vips_foreign_save_nifti_dispose( GObject *gobject )
{
	VipsForeignSaveNifti *nifti = (VipsForeignSaveNifti *) gobject;

	VIPS_FREEF( nifti_image_free, nifti->nim );

	G_OBJECT_CLASS( vips_foreign_save_nifti_parent_class )->
		dispose( gobject );
}

/* Make ->nim from the vips header fields.
 */
static int
vips_foreign_save_nifti_header_vips( VipsForeignSaveNifti *nifti, 
	VipsImage *image )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( nifti );

	int dims[8];
	int datatype;
	int i;

	/* Most nifti images have this defaulted as 1.
	 */
	for( i = 0; i < VIPS_NUMBER( dims ); i++ )
		dims[i] = 1;

	dims[0] = 2;
	dims[1] = image->Xsize;
	dims[2] = vips_image_get_page_height( image );

	/* Multipage image?
	 */
	if( dims[2] < image->Ysize ) {
		dims[0] = 3;
		dims[3] = image->Ysize / dims[2];
	}

	datatype = vips__foreign_nifti_BandFmt2datatype( image->BandFmt ); 
	if( datatype == -1 ) {
		vips_error( class->nickname, 
			"%s", _( "unsupported libvips image type" ) );
		return( -1 );
	}

	if( image->Bands > 1 ) {
		if( image->BandFmt != VIPS_FORMAT_UCHAR ) {
			vips_error( class->nickname, 
				"%s", _( "8-bit colour images only" ) );
			return( -1 );
		}

		if( image->Bands == 3 ) 
			datatype = DT_RGB;
		else if( image->Bands == 4 ) 
			datatype = DT_RGBA32;
		else {
			vips_error( class->nickname, 
				"%s", _( "3 or 4 band colour images only" ) );
			return( -1 );
		}
	}

	if( !(nifti->nim = nifti_make_new_nim( dims, datatype, FALSE )) )
		return( -1 );

	nifti->nim->dx = 1.0 / image->Xres;
	nifti->nim->dy = 1.0 / image->Yres;
	nifti->nim->dz = 1.0 / image->Yres;
	nifti->nim->xyz_units = NIFTI_UNITS_MM;

	vips_snprintf( nifti->nim->descrip, sizeof( nifti->nim->descrip ),
		"libvips-%s", VIPS_VERSION ); 

	/* All other fields can stay at their default value.
	 */

	return( 0 );
}

typedef struct _VipsNdimInfo {
	VipsImage *image;
	nifti_image *nim;
	int *dims;
	int n;
} VipsNdimInfo;

static void *
vips_foreign_save_nifti_set_dims( const char *name, 
	GValue *value, glong offset, void *a, void *b )
{
	VipsNdimInfo *info = (VipsNdimInfo *) a;

	/* The first 8 members are the dims fields. 
	 */
	if( info->n < 8 ) {
		char vips_name[256];
		int i;

		vips_snprintf( vips_name, 256, "nifti-%s", name );
		if( vips_image_get_int( info->image, vips_name, &i ) ||
			i <= 0 ||
			i >= VIPS_MAX_COORD ) 
			return( info );
		info->dims[info->n] = i;
	}

	info->n += 1;

	return( NULL ); 
}

/* How I wish glib had something like this :( Just implement the ones we need
 * for vips_foreign_nifti_fields above.
 */
static void
vips_gvalue_write( GValue *value, void *p )
{
	switch( G_VALUE_TYPE( value ) ) {
	case G_TYPE_INT:
		*((int *) p) = g_value_get_int( value );
		break;

	case G_TYPE_DOUBLE:
		*((float *) p) = g_value_get_double( value );
		break;

	default:
		g_warning( "vips_gvalue_write: unsupported GType %s", 
			g_type_name( G_VALUE_TYPE( value ) ) );
	}
}

static void *
vips_foreign_save_nifti_set_fields( const char *name, 
	GValue *value, glong offset, void *a, void *b )
{
	VipsNdimInfo *info = (VipsNdimInfo *) a;

	/* The first 8 members are the dims fields. We set them above ^^^ --
	 * do the others in this pass.
	 */
	if( info->n >= 8 ) {
		char vips_name[256];
		GValue value_copy = { 0 };

		vips_snprintf( vips_name, 256, "nifti-%s", name );
		if( vips_image_get( info->image, vips_name, &value_copy ) )
			return( info );
		vips_gvalue_write( &value_copy, (gpointer) info->nim + offset );
		g_value_unset( &value_copy );
	}

	info->n += 1;

	return( NULL ); 
}

static void *
vips_foreign_save_nifti_ext( VipsImage *image, 
	const char *field, GValue *value, void *a )
{
	nifti_image *nim = (nifti_image *) a;

	int i;
	int ecode;
	char *data;
	size_t length;

	if( !vips_isprefix( "nifti-ext-", field ) )
		return( NULL );

	/* The name is "nifti-ext-N-XX" where N is the index (discard this)
	 * and XX is the nifti ext ecode.
	 */
	if( sscanf( field, "nifti-ext-%d-%d", &i, &ecode ) != 2 ) {
		vips_error( "niftisave", 
			"%s", _( "bad nifti-ext- field name" ) ); 
		return( image );
	}

	if( vips_image_get_blob( image, field, (void *) &data, &length ) )
		return( image );

	if( nifti_add_extension( nim, data, length, ecode ) ) {
		vips_error( "niftisave", 
			"%s", _( "unable to attach nifti ext" ) ); 
		return( image );
	}

	return( NULL );
}

/* Make ->nim from the nifti- fields.
 */
static int
vips_foreign_save_nifti_header_nifti( VipsForeignSaveNifti *nifti, 
	VipsImage *image )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( nifti );

	VipsNdimInfo info;
	int dims[8];
	int datatype;
	guint height;
	int i;

	/* Most nifti images have this defaulted as 1.
	 */
	for( i = 0; i < VIPS_NUMBER( dims ); i++ )
		dims[i] = 1;

	info.image = image;
	info.dims = dims;
	info.n = 0;
	if( vips__foreign_nifti_map( 
		vips_foreign_save_nifti_set_dims, &info, NULL ) )
		return( -1 ); 

	/* page-height overrides ny if it makes sense. This might not be
	 * correct :( 
	 */
	dims[2] = vips_image_get_page_height( image );

	/* Multipage image?
	 */
	if( dims[2] < image->Ysize ) {
		dims[0] = 3;
		dims[3] = image->Ysize / dims[2];
	}

	height = 1;
	for( i = 2; i < VIPS_NUMBER( dims ) && i < dims[0] + 1; i++ )
		if( !g_uint_checked_mul( &height, height, dims[i] ) ) {
			vips_error( class->nickname, 
				"%s", _( "dimension overflow" ) ); 
			return( 0 );
		}
	if( image->Xsize != dims[1] ||
		image->Ysize != height ) {
		vips_error( class->nickname, 
			"%s", _( "bad image dimensions" ) );
		return( -1 );
	}

	datatype = vips__foreign_nifti_BandFmt2datatype( image->BandFmt ); 
	if( datatype == -1 ) {
		vips_error( class->nickname, 
			"%s", _( "unsupported libvips image type" ) );
		return( -1 );
	}

	if( !(nifti->nim = nifti_make_new_nim( dims, datatype, FALSE )) )
		return( -1 );

	info.image = image;
	info.nim = nifti->nim;
	info.n = 0;
	if( vips__foreign_nifti_map( 
		vips_foreign_save_nifti_set_fields, &info, NULL ) )
		return( -1 ); 

	/* Attach any ext blocks.
	 */
	if( vips_image_map( image,
		(VipsImageMapFn) vips_foreign_save_nifti_ext, nifti->nim ) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_save_nifti_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveNifti *nifti = (VipsForeignSaveNifti *) object;

	if( VIPS_OBJECT_CLASS( vips_foreign_save_nifti_parent_class )->
		build( object ) )
		return( -1 );

	/* This could be an image (indirectly) from niftiload, or something 
	 * like OME_TIFF, which does not have all the "nifti-ndim" fields.
	 *
	 * If it doesn't look like a nifti, try to make a nifti header from
	 * what we have.
	 */
	if( vips_image_get_typeof( save->ready, "nifti-ndim" ) ) {
		if( vips_foreign_save_nifti_header_nifti( nifti, save->ready ) )
			return( -1 );
	}
	else {
		if( vips_foreign_save_nifti_header_vips( nifti, save->ready ) )
			return( -1 );
	}

	/* set ext, plus other stuff
	 */

	if( nifti_set_filenames( nifti->nim, nifti->filename, FALSE, TRUE ) ) {
		vips_error( class->nickname, 
			"%s", _( "unable to set nifti filename" ) );
		return( -1 );
	}

	if( !(nifti->nim->data = 
		vips_image_write_to_memory( save->ready, NULL )) )
		return( -1 );

	/* No return code!??!?!!
	 */
	nifti_image_write( nifti->nim );

	/* We must free and NULL the pointer or nifti will try to free it for
	 * us.
	 */
	VIPS_FREE( nifti->nim->data );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define C VIPS_FORMAT_CHAR
#define US VIPS_FORMAT_USHORT
#define S VIPS_FORMAT_SHORT
#define UI VIPS_FORMAT_UINT
#define I VIPS_FORMAT_INT
#define F VIPS_FORMAT_FLOAT
#define X VIPS_FORMAT_COMPLEX
#define D VIPS_FORMAT_DOUBLE
#define DX VIPS_FORMAT_DPCOMPLEX

static int vips_nifti_bandfmt[10] = {
/* UC  C   US  S   UI  I   F   X   D   DX */
   UC, C,  US, S,  UI, I,  F,  X,  D,  DX
};

static void
vips_foreign_save_nifti_class_init( VipsForeignSaveNiftiClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_nifti_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "niftisave";
	object_class->description = _( "save image to nifti file" );
	object_class->build = vips_foreign_save_nifti_build;

	/* nificlib has not been fuzzed, so should not be used with
	 * untrusted input unless you are very careful.
	 */
	operation_class->flags |= VIPS_OPERATION_UNTRUSTED;

	foreign_class->suffs = vips_foreign_nifti_suffs;

	save_class->saveable = VIPS_SAVEABLE_ANY;
	save_class->format_table = vips_nifti_bandfmt;

	VIPS_ARG_STRING( class, "filename", 1, 
		_( "Filename" ),
		_( "Filename to save to" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsForeignSaveNifti, filename ),
		NULL );
}

static void
vips_foreign_save_nifti_init( VipsForeignSaveNifti *nifti )
{
}

#endif /*HAVE_NIFTI*/

/**
 * vips_niftisave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image to a file in NIFTI format. 
 *
 * Use the various NIFTI suffixes to pick the nifti save format.
 *
 * See also: vips_image_write_to_file(), vips_niftiload().
 *
 * Returns: 0 on success, -1 on error.
 */
int
vips_niftisave( VipsImage *in, const char *filename, ... )
{
	va_list ap;
	int result;

	va_start( ap, filename );
	result = vips_call_split( "niftisave", ap, in, filename );
	va_end( ap );

	return( result );
}
