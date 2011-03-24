/* wrapmany
 *
 * Modified:
 * 1/8/95 JC
 *	- buffer functions now get their own copies of the input pointer
 *	  array
 * 28/7/97 JC
 *	- amazing error ... only worked if ir and or had same valid
 * 23/1/08
 * 	- do im_wrapone() in terms of this
 * 8/10/09
 * 	- gtkdoc comments
 * 	- move im_wraptwo in here
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

typedef struct {
	im_wrapmany_fn fn;	/* Function we call */ 
	void *a, *b;		/* User values for function */
} Bundle;

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

/* Convert a VipsRegion.
 */
static int
process_region( VipsRegion *or, void *seq, void *a, void *b )
{
	VipsRegion **ir = (VipsRegion **) seq;
	Bundle *bun = (Bundle *) b;

	PEL *p[MAX_INPUT_IMAGES], *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	for( i = 0; ir[i]; i++ ) {
		if( vips_region_prepare( ir[i], &or->valid ) ) 
			return( -1 );
		p[i] = (PEL *) VIPS_REGION_ADDR( ir[i], 
			or->valid.left, or->valid.top );
	}
	p[i] = NULL;
	q = (PEL *) VIPS_REGION_ADDR( or, or->valid.left, or->valid.top );

	/* Convert linewise.
	 */
	for( y = 0; y < or->valid.height; y++ ) {
		PEL *p1[MAX_INPUT_IMAGES];

		/* Make a copy of p[] which the buffer function can mess up if
		 * it wants.
		 */
		for( i = 0; ir[i]; i++ )
			p1[i] = p[i];

		/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
		 */
		bun->fn( (void **) ((void *)p1), q, 
			or->valid.width, bun->a, bun->b );

		/* Move pointers on.
		 */
		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

/* Make a copy of an array of input images.
 */
static IMAGE **
dupims( IMAGE *out, IMAGE **in )
{
	IMAGE **new;
	int i, n;

	/* Count input images.
	 */
	for( n = 0; in[n]; n++ )
		;

	/* Allocate new array.
	 */
	if( !(new = VIPS_ARRAY( out, n + 1, IMAGE * )) )
		return( NULL );
	
	/* Copy.
	 */
	for( i = 0; i < n; i++ )
		new[i] = in[i];
	new[n] = NULL;

	return( new );
}

/**
 * im_wrapmany_fn:
 * @in: %NULL-terminated array of input buffers
 * @out: write processed pixels here
 * @width: number of pixels in buffer
 * @a: user data
 * @b: user data
 *
 * Given an array of buffers of input pixels, write a buffer of output pixels.
 */

/**
 * im_wrapmany:
 * @in: %NULL-terminated array of input images
 * @out: image to generate
 * @fn: buffer-processing function
 * @a: user data
 * @b: user data
 *
 * Wrap-up a buffer processing function as a PIO VIPS function.
 *
 * Given a NULL-terminated list of input images all of the same size, an
 * output image and a buffer processing function, make a PIO image processing
 * operation.
 *
 * See also: im_wrapone(), im_wraptwo(), im_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_wrapmany( IMAGE **in, IMAGE *out, im_wrapmany_fn fn, void *a, void *b )
{
	Bundle *bun = VIPS_NEW( out, Bundle );
	int i, n;

	/* Count input images.
	 */
	for( n = 0; in[n]; n++ )
		;
	if( n >= MAX_INPUT_IMAGES - 1 ) {
		vips_error( "im_wrapmany", "%s", _( "too many input images" ) );
		return( -1 );
	}

	/* Save args.
	 */
	if( !bun || !(in = dupims( out, in )) )
		return( -1 );
	bun->fn = fn;
	bun->a = a;
	bun->b = b;

	/* Check descriptors --- make sure that our caller has done this
	 * correctly.
	 */
	for( i = 0; i < n; i++ ) {
		if( in[i]->Xsize != out->Xsize || in[i]->Ysize != out->Ysize ) {
			vips_error( "im_wrapmany", 
				"%s", _( "descriptors differ in size" ) );
			return( -1 );
		}

		/* Check io style.
		 */
		if( im_piocheck( in[i], out ) )
			return( -1 );
	}
	
	/* Hint demand style. Being a buffer processor, we are happiest with
	 * thin strips.
	 */
        if( vips_demand_hint_array( out, VIPS_DEMAND_STYLE_THINSTRIP, in ) )
                return( -1 );

	/* Generate!
	 */
	if( im_generate( out,
		im_start_many, process_region, im_stop_many, in, bun ) )
		return( -1 );

	return( 0 );
}

static void
wrapone_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wrapone_fn) (bun->fn)) (ins[0], out, width, bun->a, bun->b );
}

/**
 * im_wrapone_fn:
 * @in: input pixels
 * @out: write processed pixels here
 * @width: number of pixels in buffer
 * @a: user data
 * @b: user data
 *
 * Given a buffer of input pixels, write a buffer of output pixels.
 */

/**
 * im_wrapone:
 * @in: input image
 * @out: image to generate
 * @fn: buffer-processing function
 * @a: user data
 * @b: user data
 *
 * Wrap-up a buffer processing function as a PIO VIPS function.
 *
 * Given an input image, an
 * output image and a buffer processing function, make a PIO image processing
 * operation.
 *
 * See also: im_wrapmany(), im_wraptwo(), im_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_wrapone( IMAGE *in, IMAGE *out, im_wrapone_fn fn, void *a, void *b )
{
	Bundle *bun = VIPS_NEW( out, Bundle );
	IMAGE *invec[2];

	/* Heh, yuk. We cast back above.
	 */
	bun->fn = (im_wrapmany_fn) fn;
	bun->a = a;
	bun->b = b;
	invec[0] = in; invec[1] = NULL;

	return( im_wrapmany( invec, out, 
		(im_wrapmany_fn) wrapone_gen, bun, NULL ) );
}

static void
wraptwo_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wraptwo_fn) (bun->fn)) (ins[0], ins[1], out, 
		width, bun->a, bun->b );
}

/**
 * im_wraptwo_fn:
 * @in1: input pixels from image 1
 * @in2: input pixels from image 2
 * @out: write processed pixels here
 * @width: number of pixels in buffer
 * @a: user data
 * @b: user data
 *
 * Given a pair of buffers of input pixels, write a buffer of output pixels.
 */

/**
 * im_wraptwo:
 * @in1: first input image
 * @in2: second input image
 * @out: image to generate
 * @fn: buffer-processing function
 * @a: user data
 * @b: user data
 *
 * Wrap-up a buffer processing function as a PIO VIPS function.
 *
 * Given a pair of input images of the same size, an
 * output image and a buffer processing function, make a PIO image processing
 * operation.
 *
 * See also: im_wrapone(), im_wrapmany(), im_generate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	im_wraptwo_fn fn, void *a, void *b )
{
	Bundle *bun = VIPS_NEW( out, Bundle );
	IMAGE *invec[3];

	bun->fn = (im_wrapmany_fn) fn;
	bun->a = a;
	bun->b = b;
	invec[0] = in1; invec[1] = in2; invec[2] = NULL;

	return( im_wrapmany( invec, out, 
		(im_wrapmany_fn) wraptwo_gen, bun, NULL ) );
}
