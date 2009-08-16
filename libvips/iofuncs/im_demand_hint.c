/* @(#) Hint to the evaluation mechanism that it should ask for output from
 * @(#) this image with a certain shape of patch. 
 * @(#)
 * @(#) int 
 * @(#) im_demand_hint( im, hint, in1, in2, ..., NULL )
 * @(#) IMAGE *im, *in1, *in2, ...;
 * @(#) im_demand_type hint;
 * @(#)
 * @(#) hint may be one of
 * @(#)
 * @(#)	IM_THINSTRIP
 * @(#)		This operation would like to output strips the width of the
 * @(#)		image and a few pels high. This is option suitable for
 * @(#)		point-to-point operations, such as those in the arithmetic
 * @(#)		package.
 * @(#)
 * @(#)		This is the fastest style for most simple operations.
 * @(#)
 * @(#)	IM_FATSTRIP
 * @(#)		This operation would like to output strips the width of the
 * @(#)		image and as high as possible. This option is suitable for
 * @(#)		area operations which do not violently transform coordinates,
 * @(#)		such as im_conv(). 
 * @(#)
 * @(#)	IM_SMALLTILE
 * @(#)		This is the most general demand format, and is the default.
 * @(#)		Output is demanded in small (around 100x100 pel) sections.
 * @(#)		This style works reasonably efficiently, even for bizzare
 * @(#)		operations like 45 degree rotate.
 * @(#)
 * @(#)	IM_ANY
 * @(#)		Not from a disc file, so any geometry is OK.
 * @(#)
 * @(#) NOTE: demand style falls back to the most restrictive in the pipeline.
 * @(#)	All pipeline elements in the pipeline must agree on IM_THINSTRIP
 * @(#)	before output will be asked for in this manner. If you do not set a
 * @(#) hint, you will get IM_SMALLTILE.
 * @(#)
 * @(#) in1, in2, ... are the images on which out will make demands. You
 * @(#) should terminate the list with NULL.
 * @(#)
 * @(#) int 
 * @(#) im_demand_hint_array( im, hint, in )
 * @(#) IMAGE *im, **in;
 * @(#) im_demand_type hint;
 * @(#)
 * @(#) As above, but in is a NULL-terminated array of input images. Use 
 * @(#) im_allocate_input_array() to build the input array.
 * @(#)
 * @(#) Returns non-zero on failure.
 * @(#) 
 *
 * Copyright: The National Gallery, 1993
 * Written on: 6/9/93
 * Modified on : 
 * 2/3/98 JC
 *	- IM_ANY added
 * 19/5/06
 * 	- minor change to rules: don't force ANY on no-input operations ...
 * 	  fails for image import
 * 1/12/06
 * 	- build parent/child links as well
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
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Max number of images we can handle.
 */
#define MAX_IMAGES (1000)

/* Given two im_demand_type, return the most restrictive.
 */
static im_demand_type
find_least( im_demand_type a, im_demand_type b )
{
	return( (im_demand_type) IM_MIN( (int) a, (int) b ) );
}

/* Set hint for this image.
 */
int 
im_demand_hint_array( IMAGE *im, im_demand_type hint, IMAGE **in )
{
	int i, len, nany;

	/* How many input images are there? And how many are IM_ANY?
	 */
	for( i = 0, len = 0, nany = 0; in[i]; i++, len++ )
		if( in[i]->dhint == IM_ANY )
			nany++;

	if( len == 0 ) 
		/* No input images? Just set the requested hint. We don't 
		 * force ANY, since the operation might be something like 
		 * tiled read of an EXR image, where we certainly don't want 
		 * ANY.
		 */
		;
	else if( nany == len ) 
		/* Special case: if all the inputs are IM_ANY, then output can 
		 * be IM_ANY regardless of what this function wants. 
		 */
		hint = IM_ANY;
	else
		/* Find the most restrictive of all the hints available to us.
		 */
		for( i = 0; i < len; i++ )
			hint = find_least( hint, in[i]->dhint );

	im->dhint = hint;

#ifdef DEBUG
        printf( "im_demand_hint_array: set dhint for \"%s\" to %s\n",
		im->filename, im_dhint2char( im->dhint ) );
#endif /*DEBUG*/

	/* im depends on all these ims.
	 */
	for( i = 0; i < len; i++ )
		im__link_make( im, in[i] );

	return( 0 );
}

/* Build an array, and call the above.
 */
int 
im_demand_hint( IMAGE *im, im_demand_type hint, ... )
{
	va_list ap;
	int i;
	IMAGE *ar[MAX_IMAGES];

	va_start( ap, hint );
	for( i = 0; i < MAX_IMAGES && (ar[i] = va_arg( ap, IMAGE * )); i++ ) 
		;
	va_end( ap );
	if( i == MAX_IMAGES ) {
		im_error( "im_demand_hint", 
			"%s", _( "too many images" ) );
		return( -1 );
	}

	return( im_demand_hint_array( im, hint, ar ) );
}
