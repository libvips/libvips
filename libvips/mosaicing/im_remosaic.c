/* Use one mosiaced file to mosaic another set of images.
 *
 * 1/11/01 JC
 *	- from global_balance
 * 25/02/02 JC
 *	- detect size change
 * 10/4/06
 * 	- spot file-not-found
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

/* Define for debug output.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/transform.h>

#include "mosaic.h"
#include "global_balance.h"

typedef struct {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	char *old_str;
	char *new_str;

	int new_len;
	int old_len;

} VipsRemosaic;

typedef VipsOperationClass VipsRemosaicClass;

G_DEFINE_TYPE( VipsRemosaic, vips_remosaic, VIPS_TYPE_OPERATION );

static IMAGE *
remosaic_fn( JoinNode *node, VipsRemosaic *remosaic )
{
	SymbolTable *st = node->st;
	IMAGE *im = node->im;

	IMAGE *out;
	char filename[FILENAME_MAX];
	char *p;

	if( !im ) {
		im_error( "im_remosaic", _( "file \"%s\" not found" ), 
			node->name );
		return( NULL );
	}

	/* Remove substring remosaic->old_str from in->filename, replace with
	 * remosaic->new_str.
	 */
	im_strncpy( filename, im->filename, FILENAME_MAX );
	if( (p = im_strrstr( filename, remosaic->old_str )) ) {
		int offset = p - &filename[0];

		im_strncpy( p, remosaic->new_str, FILENAME_MAX - offset );
		im_strncpy( p + remosaic->new_len,
			im->filename + offset + remosaic->old_len, 
			FILENAME_MAX - offset - remosaic->new_len );
	}

#ifdef DEBUG
	printf( "im_remosaic: filename \"%s\" -> \"%s\"\n", 
		im->filename, filename );
#endif /*DEBUG*/

	if( !(out = im__global_open_image( st, filename )) ) 
		return( NULL );

	if( out->Xsize != im->Xsize || out->Ysize != im->Ysize ) {
		im_error( "im_remosaic", 
			_( "substitute image \"%s\" is not "
				"the same size as \"%s\"" ), 
			filename, im->filename );
		return( NULL );
	}

	return( out );
}

static int
vips_remosaic_build( VipsObject *object )
{
	VipsRemosaic *remosaic = (VipsRemosaic *) object;

	SymbolTable *st;

	g_object_set( remosaic, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_remosaic_parent_class )->
		build( object ) )
		return( -1 );

	if( !(st = im__build_symtab( remosaic->out, SYM_TAB_SIZE )) ||
		im__parse_desc( st, remosaic->in ) )
		return( -1 );

	remosaic->old_len = strlen( remosaic->old_str );
	remosaic->new_len = strlen( remosaic->new_str );
	if( im__build_mosaic( st, remosaic->out, 
		(transform_fn) remosaic_fn, remosaic ) )
		return( -1 );

	return( 0 );
}

static void
vips_remosaic_class_init( VipsRemosaicClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *object_class = (VipsObjectClass *) class;

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "remosaic";
	object_class->description = _( "global balance an image mosaic" );
	object_class->build = vips_remosaic_build;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsRemosaic, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsRemosaic, out ) );

	VIPS_ARG_STRING( class, "old_str", 5, 
		_( "old_str" ), 
		_( "Search for this string" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRemosaic, old_str ),
		"" ); 

	VIPS_ARG_STRING( class, "new_str", 6, 
		_( "new_str" ), 
		_( "And swap for this string" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsRemosaic, new_str ),
		"" ); 

}

static void
vips_remosaic_init( VipsRemosaic *remosaic )
{
}

/**
 * vips_remosaic:
 * @in: mosaic to rebuild
 * @out: output image
 * @old_str: gamma of source images
 * @new_str: gamma of source images
 * @...: %NULL-terminated list of optional named arguments
 *
 * vips_remosaic() works rather as vips_globalbalance(). It takes apart the
 * mosaiced image @in and rebuilds it, substituting images.
 *
 * Unlike vips_globalbalance(), images are substituted based on their file‐
 * names.  The  rightmost  occurence  of the string @old_str is swapped
 * for @new_str, that file is opened, and that image substituted  for
 * the old image.
 *
 * It's convenient for multispectral images. You can mosaic one band, then
 * use that mosaic as a template for mosaicing the others automatically.
 *
 * See also: vips_globalbalance().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips_remosaic( VipsImage *in, VipsImage **out, 
	const char *old_str, const char *new_str, ... )
{
	va_list ap;
	int result;

	va_start( ap, new_str );
	result = vips_call_split( "remosaic", ap, in, out, old_str, new_str );
	va_end( ap );

	return( result );
}
