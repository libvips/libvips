/* save to nifti
 *
 * 5/7/18
 * 	- from fitssave.c
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#ifdef HAVE_CFITSIO

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
	VipsForeignLoadNifti *nifti = (VipsForeignLoadNifti *) gobject;

	VIPS_FREEF( nifti_image_free, nifti->nim );

	G_OBJECT_CLASS( vips_foreign_load_nifti_parent_class )->
		dispose( gobject );
}

/* Make ->nim from the vips header fields.
 */
static int
vips_foreign_save_nifti_header_vips( VipsForeignSaveNifti *nifti, 
	VipsImage *image )
{
	g_assert( FALSE );

	return( 0 );
}

typedef struct _VipsNdimInfo {
	VipsImage *image;
	int *dims;
	int n;
} VipsNdimInfo;

static void *
vips_foreign_save_nifti_set_dims( const char *name, GValue *value, glong offset,
	void *a, void *b )
{
	VipsNdimInfo *info = (VipsNdimInfo *) a;

	/* The first 8 members are the dims fields. 
	 */
	if( info->n < 7 ) {
		char txt[256];

		vips_snprintf( txt, 256, "nifti-%s", name );
		if( vips_image_get_int( image, name, &info->dims[i] ) )
			return( info );
	}

	info->n += 1;

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
	int height;
	int i;

	info.image = image;
	info.dims = dims;
	info.n = 0;
	if( vips__foreign_nifti_map( 
		vips_foreign_save_nifti_set_dims, &info, NULL ) )
		return( -1 ); 



	height = 1;
	for( i = 2; i < VIPS_NUMBER( dims ) && i < dims[0]; i++ )
		height *= dims[i];
	if( images->Xsize != dims[1] ||
		images->Ysize != height ) {
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

	if( !(nnifti->nim = nifti_make_new_nim( dims, datatype, FALSE )) )
		return( -1 );

	return( 0 );
}

static int
vips_foreign_save_nifti_build( VipsObject *object )
{
	VipsForeignSave *save = (VipsForeignSave *) object;
	VipsForeignSaveNifti *nifti = (VipsForeignSaveNifti *) object;
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( nifti ), 2 );

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

	if( !(nim->data = vips_image_write_memory( save->ready, NULL )) )
		return( -1 );

	/* No return code!??!?!!
	 */
	nifti_image_write( nifti->nim );

	/* We must free and NULL the pointer or nifti will try to free it for
	 * us.
	 */
	VIPS_FREE( nim->data );

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
	VipsForeignClass *foreign_class = (VipsForeignClass *) class;
	VipsForeignSaveClass *save_class = (VipsForeignSaveClass *) class;

	gobject_class->dispose = vips_foreign_save_nifti_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "niftisave";
	object_class->description = _( "save image to nifti file" );
	object_class->build = vips_foreign_save_nifti_build;

	foreign_class->suffs = vips__nifti_suffs;

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

#endif /*HAVE_CFITSIO*/

/**
 * vips_niftisave: (method)
 * @in: image to save 
 * @filename: file to write to 
 * @...: %NULL-terminated list of optional named arguments
 *
 * Write a VIPS image to a file in NIFTI format.
 *
 * See also: vips_image_write_to_file().
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
