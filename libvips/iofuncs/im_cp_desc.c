/* @(#)  Function which copies IMAGE descriptor image2 to image1;
 * @(#) data, fd and filename are not copied
 * @(#) used to make programs simpler by copying most parameters
 * @(#) 
 * @(#) int 
 * @(#) im_cp_desc( image1, image2 )
 * @(#) IMAGE *image1, *image2;
 * @(#)
 * @(#) Returns 0 on success or -1 on fail.
 * @(#)
 *
 * Copyright: Nicos Dessipris
 * Written on: 09/02/1990
 * Modified on : 22/2/93 By Kirk Martinez: v6.3
 * 28/10/1992 J.Cupitt
 *	- now calls im_cp_Hist, and hence frees old history correctly
 * 10/5/93 J.Cupitt
 *	- checks return result from im_cp_Hist()
 * 22/11/00 JC
 *	- ANSIfied
 * 5/9/02 JC
 *	- copy Xoffset/Yoffset too
 * 14/4/04 JC
 *	- hmm, in fact no, zero them
 * 6/6/05 Markus Wollgarten
 *	- copy Meta
 * 29/8/05
 * 	- added im_cp_descv() and im_cp_desc_array()
 * 2/9/05
 * 	- simplified ... no more skip the first line stuff
 * 4/1/07
 * 	- merge hists with history_list instead
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * im_cp_desc_array:
 * @out: image to copy to
 * @in: %NULL-terminated array of images to copy from
 *
 * Copy fields from all the input images to the output image. There must be at
 * least one input image. If you are making an image which has no input images
 * (for example, im_black() or im_vips2jpeg()), use im_initdesc() instead.
 *
 * The first input image is used to set the main fields of @out (@XSize, @Coding
 * and so on). 
 *
 * Metadata from all the image is merged on to @out, with lower-numbered items 
 * overriding higher. So for example, if @in[0] and @in[1] both have an item
 * called "icc-profile", it's the profile attached to @in[0] that will end up
 * on @out.
 *
 * Image history is completely copied from all @in. @out will have the history
 * of all the intput images.
 *
 * See also: im_cp_descv(), im_cp_desc().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_cp_desc_array( IMAGE *out, IMAGE *in[] )
{
	int i;
	int ni;

	g_assert( in[0] );

	out->Xsize = in[0]->Xsize;
	out->Ysize = in[0]->Ysize;
	out->Bands = in[0]->Bands;
	out->Bbits = in[0]->Bbits;
	out->BandFmt = in[0]->BandFmt;
	out->Type = in[0]->Type;
	out->Coding = in[0]->Coding;
	out->Xres = in[0]->Xres;
	out->Yres = in[0]->Yres;
	out->Xoffset = 0;
	out->Yoffset = 0;

	/* Count number of images.
	 */
	for( ni = 0; in[ni]; ni++ ) 
		;

	/* Need to copy last-to-first so that in0 meta will override any
	 * earlier meta.
	 */
	im__meta_destroy( out );
	for( i = ni - 1; i >= 0; i-- ) 
		if( im__meta_cp( out, in[i] ) )
			return( -1 );

	/* Merge hists first to last.
	 */
	for( i = 0; in[i]; i++ )
		out->history_list = im__gslist_gvalue_merge( out->history_list,
			in[i]->history_list );

	return( 0 );
}

/* Max number of images we can handle.
 */
#define MAX_IMAGES (1000)

/**
 * im_cp_descv:
 * @out: image to copy to
 * @in1: first image to copy from
 * @Varargs: %NULL-terminated list of images to copy from
 *
 * Copy fields from all the input images to the output image. A convenience
 * function over im_cp_desc_array(). 
 *
 * See also: im_cp_desc_array(), im_cp_desc().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_cp_descv( IMAGE *out, IMAGE *in1, ... )
{
	va_list ap;
	int i;
	IMAGE *in[MAX_IMAGES];

	in[0] = in1;
	va_start( ap, in1 );
	for( i = 1; i < MAX_IMAGES && (in[i] = va_arg( ap, IMAGE * )); i++ ) 
		;
	va_end( ap );
	if( i == MAX_IMAGES ) {
		im_error( "im_cp_descv", 
			"%s", _( "too many images" ) );
		return( -1 );
	}

	return( im_cp_desc_array( out, in ) );
}

/**
 * im_cp_desc:
 * @out: image to copy to
 * @in: image to copy from
 *
 * Copy fields from @in to @out. A convenience
 * function over im_cp_desc_array(). 
 *
 * See also: im_cp_desc_array(), im_cp_descv().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_cp_desc( IMAGE *out, IMAGE *in )
{
	return( im_cp_descv( out, in, NULL ) ); 
}
