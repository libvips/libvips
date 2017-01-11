/* recomp.c ... manage recomp reordering
 *
 * 11/1/17
 * 	- first version
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
 */
#define DEBUG

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

/* Have one of these on every image, identified by a quark.
 */
typedef struct _VipsRecomp {
	/* The image we are attached to.
	 */
	VipsImage *image;

	/* The direct inputs to this image, so a copy of the array that is
	 * passed to vips_image_pipeline_array(), and in the same order.
	 * NULL-terminated.
	 *
	 * Score is the priority we give to the inputs as we de-dupe the source
	 * arrays. 
	 *
	 * The recomp order is the order we prepare regions in ... just sort
	 * recomp_order by score.
	 */
	int n_inputs;
	VipsImage **input;
	int *score;
	int *recomp_order;

	/* Source images are images with no input images, so file load, 
	 * vips_black(), etc. NULL-terminated array.
	 *
	 * The cumulative margin is the total margin that has been added to 
	 * each source image up to this point in the pipeline.
	 */
	int n_sources;
	VipsImage **source;
	int *cumulative_margin;

} VipsRecomp;

GQuark vips__image_recomp_quark = 0; 

#ifdef DEBUG
static void
vips_recomp_print( VipsRecomp *recomp )
{
	int i;

	printf( "vips_recomp_print: " );
	vips_object_print_name( VIPS_OBJECT( recomp->image ) );
	printf( "\n" );

	printf( "n_inputs = %d\n", recomp->n_inputs );
	printf( " n      score       order\n" );
	for( i = 0; i < recomp->n_inputs; i++ ) {
		printf( "%2d - %8d, %8d, ", 
			i, recomp->score[i], recomp->recomp_order[i] );
		vips_object_print_name( VIPS_OBJECT( recomp->input[i] ) );
		printf( "\n" );
	}

	printf( "n_sources = %d\n", recomp->n_sources );
	printf( " n     margin\n" );
	for( i = 0; i < recomp->n_sources; i++ ) {
		printf( "%2d - %8d, ", 
			i, recomp->cumulative_margin[i] );
		vips_object_print_name( VIPS_OBJECT( recomp->source[i] ) );
		printf( "\n" );
	}

}
#endif /*DEBUG*/

static VipsRecomp *
vips_recomp_get( VipsImage *image )
{
	VipsRecomp *recomp;
		
	if( (recomp = g_object_get_qdata( G_OBJECT( image ), 
		vips__image_recomp_quark )) ) 
		return( recomp );

	recomp = VIPS_NEW( image, VipsRecomp );
	recomp->image = image;
	recomp->n_inputs = 0;
	recomp->input = NULL;
	recomp->score = NULL;
	recomp->recomp_order = NULL;
	recomp->n_sources = 0;
	recomp->source = NULL;
	recomp->cumulative_margin = NULL;

	g_object_set_qdata( G_OBJECT( image ), vips__image_recomp_quark, 
		recomp );

	return( recomp );
}

static int
vips_recomp_compare_score( const void *a, const void *b, void *arg )
{
	int i1 = *((int *) a);
	int i2 = *((int *) b);
	VipsRecomp *recomp = (VipsRecomp *) arg;

	return( recomp->score[i1] - recomp->score[i2] );
}

int
vips__recomp_set_input( VipsImage *image, VipsImage **in )
{
	VipsRecomp *recomp = vips_recomp_get( image );

	int i;
	int total;

	printf( "vips__recomp_set_input: starting for image %p\n", image ); 

	/* We have to support being called more than once on the same image.
	 * Two cases: 
	 * 
	 * 1. in the first call, no images were set ... we throw away
	 * everything from the first call and try again. foreign can do this.
	 *
	 * 2. warn if the args were different and do nothing.
	 */
	if( recomp->source ) {
		printf( "vips__recomp_set_input: run again\n" ); 

		if( recomp->n_inputs == 0 ) {
			printf( "vips__recomp_set_input: "
				"no args to first call\n" ); 

			recomp->n_sources = 0;
		}
		else {
			for( i = 0; in[i]; i++ )
				if( i >= recomp->n_inputs ||
					in[i] != recomp->input[i] ) {
					printf( "vips__recomp_set_input: "
						"args differ\n" );
					break;
				}

			return( 0 );
		}
	}

	/* Make a copy of the input array.
	 */
	for( i = 0; in[i]; i++ )
		;
	recomp->n_inputs = i;
	recomp->input = VIPS_ARRAY( image, recomp->n_inputs + 1, VipsImage * );
	recomp->score = VIPS_ARRAY( image, recomp->n_inputs, int );
	recomp->recomp_order = VIPS_ARRAY( image, recomp->n_inputs, int );
	if( !recomp->input )
		return( -1 );
	if( recomp->n_inputs && 
		(!recomp->score ||
		 !recomp->recomp_order) )
		return( -1 );

	for( i = 0; i < recomp->n_inputs; i++ ) {
		recomp->input[i] = in[i];
		recomp->score[i] = 0;
		recomp->recomp_order[i] = i;
	}
	recomp->input[i] = NULL;

	/* Find the total number of source images -- this gives an upper bound
	 * to the size of the unique source image array we will need.
	 */
	total = 0;
	for( i = 0; i < recomp->n_inputs; i++ ) 
		total += vips_recomp_get( recomp->input[i] )->n_sources;

	/* No source images means this must itself be a source image, so it has
	 * a source image of itself.
	 */
	total = VIPS_MAX( 1, total );

	recomp->source = VIPS_ARRAY( image, total + 1, VipsImage * );
	recomp->cumulative_margin = VIPS_ARRAY( image, total, int );
	if( !recomp->source ||
		!recomp->cumulative_margin )
		return( -1 );

	/* Copy source images over, removing duplicates. If we find a
	 * duplicate, we have a reordering opportunity, and we adjust the
	 * scores of the two images containing the dupe.
	 */
	for( i = 0; i < recomp->n_inputs; i++ ) {
		VipsRecomp *input = vips_recomp_get( recomp->input[i] );

		int j;

		for( j = 0; j < input->n_sources; j++ ) {
			int k;

			/* Search for dupe.
			 */
			for( k = 0; k < recomp->n_sources; k++ )
				if( recomp->source[k] == input->source[j] )
					break;

			if( k < recomp->n_sources ) {
				/* Found a dupe. Does this new use of
				 * input->source[j] have a larger or smaller
				 * margin? Adjust the score to reflect the
				 * change, note the new max.
				 */
				recomp->cumulative_margin[k] = VIPS_MAX(
					recomp->cumulative_margin[k],
					input->cumulative_margin[j] );
				recomp->score[i] += input->cumulative_margin[j] -
					recomp->cumulative_margin[k];
			}
			else {
				/* No dupe, just add to the table.
				 */
				recomp->source[recomp->n_sources] = 
					input->source[j];
				recomp->cumulative_margin[recomp->n_sources] = 
					input->cumulative_margin[j];
				recomp->n_sources += 1;

				vips_recomp_print( recomp );
			}
		}
	}

	/* Sort recomp_order by score. qsort_r() is a GNU libc thing, don't use
	 * it.
	 */
	if( recomp->n_inputs > 1 ) 
		g_qsort_with_data( recomp->recomp_order, 
			recomp->n_inputs, 
			sizeof( int ), 
			vips_recomp_compare_score, recomp );

	/* No sources ... make one, us!
	 */
	if( recomp->n_inputs == 0 ) {
		recomp->source[0] = image;
		recomp->cumulative_margin[0] = 0;
		recomp->n_sources = 1;
	}

#ifdef DEBUG
	vips_recomp_print( recomp );
#endif /*DEBUG*/

	return( 0 );
}

int
vips_image_prepare_many( VipsImage *image, VipsRegion **regions, VipsRect *r )
{
	VipsRecomp *recomp = vips_recomp_get( image );

	int i;

	for( i = 0; i < recomp->n_inputs; i++ ) { 
		g_assert( regions[i] );

		if( vips_region_prepare( regions[recomp->recomp_order[i]], r ) )
			return( -1 );
	}

	return( 0 );
}

void
vips__recomp_add_margin( VipsImage *image, int margin )
{
	VipsRecomp *recomp = vips_recomp_get( image );

	int i;

	for( i = 0; i < recomp->n_sources; i++ )  
		recomp->cumulative_margin[i] += margin;
}

void
vips__recomp_init( void )
{
	if( !vips__image_recomp_quark )
		vips__image_recomp_quark = 
			g_quark_from_static_string( "vips-image-recomp" ); 
}
