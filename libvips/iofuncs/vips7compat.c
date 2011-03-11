/* compat stuff for vips7
 * 
 * 4/3/11
 * 	- hacked up 
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

/*
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Just for compatibility. New code should use vips_object_local() directly.
 */
VipsImage *
im_open_local( VipsImage *parent, 
	const char *filename, const char *mode )
{
	VipsImage *image;

	if( !(image = vips_image_new_from_file( filename, mode )) )
		return( NULL );
	vips_object_local( parent, image );

	return( image );
}

/* Just for compatibility. New code should use vips_image_new_array().
 */
int
im_open_local_array( VipsImage *parent, 
	VipsImage **images, int n,
	const char *filename, const char *mode )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(images[i] = im_open_local( parent, filename, mode )) )
			return( -1 );

	return( 0 );
}

typedef struct {
	im_callback_fn fn;
	void *a;
	void *b;
} Callback;

static void
im_add_callback_cb( VipsImage *im, Callback *callback )
{
	if( callback->fn( callback->a, callback->b ) )
		vips_image_set_kill( im, TRUE );
}

int 
im_add_callback( VipsImage *im, 
	const char *name, im_callback_fn fn, void *a, void *b )
{
	Callback *callback;

	if( !(callback = VIPS_NEW( im, Callback )) )
		return( -1 );
	callback->fn = fn;
	callback->a = a;
	callback->b = b;
	g_signal_connect( im, name,
		G_CALLBACK( im_add_callback_cb ), callback );

	return( 0 );
}

/* Make something local to an image descriptor ... pass in a constructor
 * and a destructor, plus three args.
 */
void *
im_local( IMAGE *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	void *obj;

	if( !im ) {
		im_error( "im_local", "%s", _( "NULL image descriptor" ) );
		return( NULL );
	}

        if( !(obj = cons( a, b, c )) )
                return( NULL );
        if( im_add_close_callback( im, (im_callback_fn) dest, obj, a ) ) {
                dest( obj, a );
                return( NULL );
        }
 
        return( obj );
}

/* Make an array of things local to a descriptor ... eg. make 6 local temp
 * images.
 */
int
im_local_array( IMAGE *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(out[i] = im_local( im, cons, dest, a, b, c )) )
			return( -1 );

	return( 0 );
}

int
im_close( VipsImage *im )
{
	g_object_unref( im );

	return( 0 );
}

/* edvips.c needs this
 */
VipsImage *
im_init( const char *filename )
{
	VipsImage *image;

	image = vips_image_new( "p" );
	VIPS_SETSTR( image->filename, filename );

	return( image );
}

/* Prettyprint various header fields. Just for vips7 compat, use
 * VIPS_ENUM_VALUE() instead.
 */
const char *im_Type2char( VipsInterpretation type ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_INTERPRETATION, type ) ); }
const char *im_BandFmt2char( VipsBandFormat format ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_BAND_FORMAT, format ) ); }
const char *im_Coding2char( VipsCoding coding ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_CODING, coding ) ); }
const char *im_dtype2char( VipsImageType n ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_IMAGE_TYPE, n ) ); }
const char *im_dhint2char( VipsDemandStyle style ) 
	{ return( VIPS_ENUM_STRING( VIPS_TYPE_DEMAND_STYLE, style ) ); }

VipsInterpretation im_char2Type( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_INTERPRETATION, str ) ); }
VipsBandFormat im_char2BandFmt( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_BAND_FORMAT, str ) ); }
VipsCoding im_char2Coding( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_CODING, str ) ); }
VipsImageType im_char2dtype( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_IMAGE_TYPE, str ) ); }
VipsDemandStyle im_char2dhint( const char *str ) 
	{ return( VIPS_ENUM_VALUE( VIPS_TYPE_DEMAND_STYLE, str ) ); }

/* Totally useless now.
 */
const char *im_Compression2char( int n ) { return( "NONE" ); }
int im_char2Compression( const char *str ) { return( -1 ); }

