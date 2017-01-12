/* reorder.c ... manage reorder reordering
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
typedef struct _VipsReorder {
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
	 * The recomp order is the order we prepare regions in ... just make a
	 * range then sort by score.
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

} VipsReorder;

GQuark vips__image_reorder_quark = 0; 

#ifdef DEBUG
static void
vips_reorder_print( VipsReorder *reorder )
{
	int i;

	printf( "vips_reorder_print: " );
	vips_object_print_name( VIPS_OBJECT( reorder->image ) );
	printf( "\n" );

	printf( "n_inputs = %d\n", reorder->n_inputs );
	printf( " n      score       order\n" );
	for( i = 0; i < reorder->n_inputs; i++ ) {
		printf( "%2d - %8d, %8d, ", 
			i, reorder->score[i], reorder->recomp_order[i] );
		vips_object_print_name( VIPS_OBJECT( reorder->input[i] ) );
		printf( "\n" );
	}

	printf( "n_sources = %d\n", reorder->n_sources );
	printf( " n     margin\n" );
	for( i = 0; i < reorder->n_sources; i++ ) {
		printf( "%2d - %8d, ", 
			i, reorder->cumulative_margin[i] );
		vips_object_print_name( VIPS_OBJECT( reorder->source[i] ) );
		printf( "\n" );
	}

}
#endif /*DEBUG*/

static VipsReorder *
vips_reorder_get( VipsImage *image )
{
	VipsReorder *reorder;
		
	if( (reorder = g_object_get_qdata( G_OBJECT( image ), 
		vips__image_reorder_quark )) ) 
		return( reorder );

	reorder = VIPS_NEW( image, VipsReorder );
	reorder->image = image;
	reorder->n_inputs = 0;
	reorder->input = NULL;
	reorder->score = NULL;
	reorder->recomp_order = NULL;
	reorder->n_sources = 0;
	reorder->source = NULL;
	reorder->cumulative_margin = NULL;

	g_object_set_qdata( G_OBJECT( image ), vips__image_reorder_quark, 
		reorder );

	return( reorder );
}

static int
vips_reorder_compare_score( const void *a, const void *b, void *arg )
{
	int i1 = *((int *) a);
	int i2 = *((int *) b);
	VipsReorder *reorder = (VipsReorder *) arg;

	return( reorder->score[i2] - reorder->score[i1] );
}

int
vips__reorder_set_input( VipsImage *image, VipsImage **in )
{
	VipsReorder *reorder = vips_reorder_get( image );

	int i;
	int total;

	printf( "vips__reorder_set_input: starting for image %p\n", image ); 

	/* We have to support being called more than once on the same image.
	 * Two cases: 
	 * 
	 * 1. in the first call, no images were set ... we throw away
	 * everything from the first call and try again. foreign can do this.
	 *
	 * 2. warn if the args were different and do nothing.
	 */
	if( reorder->source ) {
		printf( "vips__reorder_set_input: run again\n" ); 

		if( reorder->n_inputs == 0 ) {
			printf( "vips__reorder_set_input: "
				"no args to first call\n" ); 

			reorder->n_sources = 0;
		}
		else {
			for( i = 0; in[i]; i++ )
				if( i >= reorder->n_inputs ||
					in[i] != reorder->input[i] ) {
					printf( "vips__reorder_set_input: "
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
	reorder->n_inputs = i;
	reorder->input = VIPS_ARRAY( image, reorder->n_inputs + 1, VipsImage * );
	reorder->score = VIPS_ARRAY( image, reorder->n_inputs, int );
	reorder->recomp_order = VIPS_ARRAY( image, reorder->n_inputs, int );
	if( !reorder->input )
		return( -1 );
	if( reorder->n_inputs && 
		(!reorder->score ||
		 !reorder->recomp_order) )
		return( -1 );

	for( i = 0; i < reorder->n_inputs; i++ ) {
		reorder->input[i] = in[i];
		reorder->score[i] = 0;
		reorder->recomp_order[i] = i;
	}
	reorder->input[i] = NULL;

	/* Find the total number of source images -- this gives an upper bound
	 * to the size of the unique source image array we will need.
	 */
	total = 0;
	for( i = 0; i < reorder->n_inputs; i++ ) 
		total += vips_reorder_get( reorder->input[i] )->n_sources;

	/* No source images means this must itself be a source image, so it has
	 * a source image of itself.
	 */
	total = VIPS_MAX( 1, total );

	reorder->source = VIPS_ARRAY( image, total + 1, VipsImage * );
	reorder->cumulative_margin = VIPS_ARRAY( image, total, int );
	if( !reorder->source ||
		!reorder->cumulative_margin )
		return( -1 );

	/* Copy source images over, removing duplicates. If we find a
	 * duplicate, we have a reordering opportunity, and we adjust the
	 * scores of the two images containing the dupe.
	 */
	for( i = 0; i < reorder->n_inputs; i++ ) {
		VipsReorder *input = vips_reorder_get( reorder->input[i] );

		int j;

		for( j = 0; j < input->n_sources; j++ ) {
			int k;

			/* Search for dupe.
			 */
			for( k = 0; k < reorder->n_sources; k++ )
				if( reorder->source[k] == input->source[j] )
					break;

			if( k < reorder->n_sources ) {
				/* Found a dupe. Does this new use of
				 * input->source[j] have a larger or smaller
				 * margin? Adjust the score to reflect the
				 * change, note the new max.
				 */

				printf( "found a dupe\n" );
				printf( "margin on first one %d\n", 
					reorder->cumulative_margin[k] );
				printf( "margin on new one %d\n", 
					input->cumulative_margin[j] );
					
				printf( "setting score on %d += %d\n", 
					i, input->cumulative_margin[j] - 
						reorder->cumulative_margin[k] );

				reorder->cumulative_margin[k] = VIPS_MAX(
					reorder->cumulative_margin[k],
					input->cumulative_margin[j] );
				reorder->score[i] += input->cumulative_margin[j] -
					reorder->cumulative_margin[k];

			}
			else {
				/* No dupe, just add to the table.
				 */
				reorder->source[reorder->n_sources] = 
					input->source[j];
				reorder->cumulative_margin[reorder->n_sources] = 
					input->cumulative_margin[j];
				reorder->n_sources += 1;

				vips_reorder_print( reorder );
			}
		}
	}

	/* Sort recomp_order by score. qsort_r() is a GNU libc thing, don't use
	 * it.
	 */
	if( reorder->n_inputs > 1 ) 
		g_qsort_with_data( reorder->recomp_order, 
			reorder->n_inputs, 
			sizeof( int ), 
			vips_reorder_compare_score, reorder );

	/* No sources ... make one, us!
	 */
	if( reorder->n_inputs == 0 ) {
		reorder->source[0] = image;
		reorder->cumulative_margin[0] = 0;
		reorder->n_sources = 1;
	}

#ifdef DEBUG
	vips_reorder_print( reorder );
#endif /*DEBUG*/

	return( 0 );
}

int
vips_image_prepare_many( VipsImage *image, VipsRegion **regions, VipsRect *r )
{
	VipsReorder *reorder = vips_reorder_get( image );

	int i;

	for( i = 0; i < reorder->n_inputs; i++ ) { 
		g_assert( regions[i] );

		if( vips_region_prepare( regions[reorder->recomp_order[i]], r ) )
			return( -1 );
	}

	return( 0 );
}

void
vips__reorder_add_margin( VipsImage *image, int margin )
{
	VipsReorder *reorder = vips_reorder_get( image );

	int i;

	for( i = 0; i < reorder->n_sources; i++ )  
		reorder->cumulative_margin[i] += margin;
}

void
vips__reorder_init( void )
{
	if( !vips__image_reorder_quark )
		vips__image_reorder_quark = 
			g_quark_from_static_string( "vips-image-reorder" ); 
}
