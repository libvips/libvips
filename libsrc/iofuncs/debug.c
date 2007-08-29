/* debug.c: support for debugging
 *
 * 24/10/95 JC
 *	- first version
 * 24/2/05
 *	- print more mem allocation info
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
#include <stdlib.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Track all open images in this.
 */
GSList *im__open_images = NULL;

static void *
print_one_line_region( REGION *r, int *n2, int *total )
{
	if( r->type == IM_REGION_BUFFER && r->buffer ) {
		printf( "\t*** %d) %zd malloced bytes\n", 
			*n2, r->buffer->bsize );
		*total += r->buffer->bsize;
	}

	*n2 += 1;

	return( NULL );
}

/* Print a one-line description of an image, with an index.
 */
static void *
print_one_line( IMAGE *im, int *n, int *total )
{
	printf( "%2d) %p, %s, %s: %dx%d, %d bands, %s\n",
		*n, 
		im,
		im_dtype2char( im->dtype ), im->filename, 
		im->Xsize, im->Ysize, im->Bands,
		im_BandFmt2char( im->BandFmt ) );
	*n += 1;

	if( im->dtype == IM_SETBUF && im->data ) {
		int size = IM_IMAGE_SIZEOF_LINE( im ) * im->Ysize;

		printf( "\t*** %d malloced bytes\n", size );
		*total += size;
	}

	if( im->regions ) {
		int n2;
		int total2;

		printf( "\t%d regions\n", g_slist_length( im->regions ) );
		n2 = 0;
		total2 = 0;
		(void) im_slist_map2( im->regions, 
			(VSListMap2Fn) print_one_line_region, &n2, &total2 );
		if( total2 )
			printf( "\t*** using total of %d bytes\n", total2 );
		*total += total2;
	}

	return( NULL );
}

/* Print one line for each open descriptor.
 */
void
im__print_all( void )
{
	int n = 0;
	int total = 0;

	if( im__open_images ) {
		printf( "%d images\n", g_slist_length( im__open_images ) );
		(void) im_slist_map2( im__open_images, 
			(VSListMap2Fn) print_one_line, &n, &total );
		if( total )
			printf( "\n\t*** all-image total = %d bytes\n", total );
	}
}

/* Debugging: given an index, print everything we know about that descriptor.
 */
void
im__print_one( int n )
{
	IMAGE *im = g_slist_nth_data( im__open_images, n );

	if( !im ) {
		printf( "bad index: %d\n", n );
		return;
	}

	im_printdesc( im );
}
