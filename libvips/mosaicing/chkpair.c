/* find image overlaps 
 *
 * Copyright: 1990, N. Dessipris.
 *
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on : 18/04/1991
 * 8/7/93 JC
 *	- allows IM_CODING_LABQ coding
 *	- now calls im_incheck()
 * 13/7/95 JC
 *	- rewritten
 *	- now uses im_spcor()
 * 13/8/96 JC
 *	- order of args changed to help C++ API
 * 24/1/11
 * 	- gtk-doc
 * 18/6/20 kleisauke
 * 	- convert to vips8
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
#include <glib/gi18n-lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>

#include "pmosaicing.h"

/* vips__correl:
 * @ref: reference image
 * @sec: secondary image
 * @xref: position in reference image
 * @yref: position in reference image
 * @xsec: position in secondary image
 * @ysec: position in secondary image
 * @hwindowsize: half window size
 * @hsearchsize: half search size 
 * @correlation: return detected correlation
 * @x: return found position
 * @y: return found position
 *
 * This operation finds the position of @sec within @ref. 
 *
 * The area around
 * (@xsec, @ysec) is searched for the best match to the area around (@xref,
 * @yref). It  searches an area of size @hsearchsize for a
 * match of size @hwindowsize.  The position of the best match is
 * returned, together with the correlation at that point.
 *
 * Only  the  first  band  of each image is correlated. @ref and @sec may be
 * very large --- the function  extracts  and  generates  just  the
 * parts needed.  Correlation is done with vips_spcor(); the position of
 * the maximum is found with vips_max().
 * 
 * See also: vips_match(), vips__lrmosaic().
 *
 * Returns: 0 on success, -1 on error
 */
int 
vips__correl( VipsImage *ref, VipsImage *sec, 
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	double *correlation, int *x, int *y )
{
	VipsImage *surface = vips_image_new();
	VipsImage **t = (VipsImage **)
		vips_object_local_array( VIPS_OBJECT( surface ), 5 );

	VipsRect refr, secr;
	VipsRect winr, srhr;
	VipsRect wincr, srhcr;
	
	/* Find position of window and search area, and clip against image
	 * size.
	 */
	refr.left = 0;
	refr.top = 0;
	refr.width = ref->Xsize;
	refr.height = ref->Ysize;
	winr.left = xref - hwindowsize;
	winr.top = yref - hwindowsize;
	winr.width = hwindowsize * 2 + 1;
	winr.height = hwindowsize * 2 + 1;
	vips_rect_intersectrect( &refr, &winr, &wincr );

	secr.left = 0;
	secr.top = 0;
	secr.width = sec->Xsize;
	secr.height = sec->Ysize;
	srhr.left = xsec - hsearchsize;
	srhr.top = ysec - hsearchsize;
	srhr.width = hsearchsize * 2 + 1;
	srhr.height = hsearchsize * 2 + 1;
	vips_rect_intersectrect( &secr, &srhr, &srhcr );

	/* Extract window and search area.
	 */
	if( vips_extract_area( ref, &t[0], 
			wincr.left, wincr.top, wincr.width, wincr.height, 
			NULL ) ||
		vips_extract_area( sec, &t[1], 
			srhcr.left, srhcr.top, srhcr.width, srhcr.height, 
			NULL ) ) {
		g_object_unref( surface );
		return( -1 );
	}
	ref = t[0];
	sec = t[1];

	/* Make sure we have just one band. From vips_*mosaic() we will, but
	 * from vips_match() etc. we may not.
	 */
	if( ref->Bands != 1 ) {
		if( vips_extract_band( ref, &t[2], 0, NULL ) ) {
			g_object_unref( surface );
			return( -1 );
		}
		ref = t[2];
	}
	if( sec->Bands != 1 ) {
		if( vips_extract_band( sec, &t[3], 0, NULL ) ) {
			g_object_unref( surface );
			return( -1 );
		}
		sec = t[3];
	}

	/* Search!
	 */
	if( vips_spcor( sec, ref, &t[4], NULL ) ) {
		g_object_unref( surface );
		return( -1 );
	}

	/* Find maximum of correlation surface.
	 */
	if( vips_max( t[4], correlation, "x", x, "y", y, NULL ) ) {
		g_object_unref( surface );
		return( -1 );
	}
	g_object_unref( surface );

	/* Translate back to position within sec.
	 */
	*x += srhcr.left;
	*y += srhcr.top;

	return( 0 );
}

int 
vips__chkpair( VipsImage *ref, VipsImage *sec, TiePoints *points )
{
	int i;
	int x, y;
	double correlation;

	const int hcor = points->halfcorsize;
	const int harea = points->halfareasize;

	/* Check images.
	 */
	if( vips_image_wio_input( ref ) || vips_image_wio_input( sec ) ) 
		return( -1 );
	if( ref->Bands != sec->Bands || ref->BandFmt != sec->BandFmt || 
		ref->Coding != sec->Coding ) {
		vips_error( "vips_chkpair", "%s", _( "inputs incompatible" ) ); 
		return( -1 ); 
	}
	if( ref->Bands != 1 || ref->BandFmt != VIPS_FORMAT_UCHAR ) {
		vips_error( "vips_chkpair", "%s", _( "help!" ) );
		return( -1 );
	}

	for( i = 0; i < points->nopoints; i++ ) {
		/* Find correlation point.
		 */
		if( vips__correl( ref, sec, 
			points->x_reference[i], points->y_reference[i],
			points->x_reference[i], points->y_reference[i],
			hcor, harea, 
			&correlation, &x, &y ) ) 
			return( -1 );

		/* And note in x_secondary.
		 */
		points->x_secondary[i] = x;
		points->y_secondary[i] = y;
		points->correlation[i] = correlation;

		/* Note each dx, dy too.
		 */
		points->dx[i] = 
			points->x_secondary[i] - points->x_reference[i];
		points->dy[i] = 
			points->y_secondary[i] - points->y_reference[i];
	}

	return( 0 );
}
