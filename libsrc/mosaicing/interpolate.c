/* vipsinterpolate ... abstract base class for various interpolators
 *
 * J. Cupitt, 15/10/08
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

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* "fast" floor() ... on my laptop, anyway.
 */
#define FLOOR( V ) ((V) >= 0 ? (int)(V) : (int)((V) - 1))

static VipsObjectClass *vips_interpolate_parent_class = NULL;
static VipsObjectClass *vips_interpolate_nearest_parent_class = NULL;
static VipsObjectClass *vips_interpolate_bilinear_parent_class = NULL;

#ifdef DEBUG
static void
vips_interpolate_finalize( GObject *gobject )
{
	printf( "vips_interpolate_finalize: " );
	vips_object_print( VIPS_OBJECT( gobject ) );

	G_OBJECT_CLASS( vips_interpolate_parent_class )->finalize( gobject );
}
#endif /*DEBUG*/

static int
vips_interpolate_real_get_window_size( VipsInterpolate *interpolate )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->window_size != -1 );

	return( class->window_size );
}

static void
vips_interpolate_class_init( VipsInterpolateClass *class )
{
#ifdef DEBUG
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
#endif /*DEBUG*/

	vips_interpolate_parent_class = g_type_class_peek_parent( class );

#ifdef DEBUG
	gobject_class->finalize = vips_interpolate_finalize;
#endif /*DEBUG*/
	class->interpolate = NULL;
	class->get_window_size = vips_interpolate_real_get_window_size;
	class->window_size = -1;
}

static void
vips_interpolate_init( VipsInterpolate *interpolate )
{
#ifdef DEBUG
	printf( "vips_interpolate_init: " );
	vips_object_print( VIPS_OBJECT( interpolate ) );
#endif /*DEBUG*/
}

GType
vips_interpolate_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		static const GTypeInfo info = {
			sizeof( VipsObjectClass ),
			NULL,           /* base_init */
			NULL,           /* base_finalize */
			(GClassInitFunc) vips_interpolate_class_init,
			NULL,           /* class_finalize */
			NULL,           /* class_data */
			sizeof( VipsObject ),
			32,             /* n_preallocs */
			(GInstanceInitFunc) vips_interpolate_init,
		};

		type = g_type_register_static( VIPS_TYPE_OBJECT, 
			"VipsInterpolate", &info, 0 );
	}

	return( type );
}

/* Set the point out_x, out_y in REGION out to be the point interpolated at
 * in_x, in_y in REGION in. Don't do this as a signal ffor speed.
 */
void
vips_interpolate( VipsInterpolate *interpolate, REGION *out, REGION *in,
	int out_x, int out_y, double in_x, double in_y )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->interpolate );
	class->interpolate( interpolate, out, in, out_x, out_y, in_x, in_y );
}

/* Get this interpolator's required window size.
 */
int
vips_interpolate_get_window_size( VipsInterpolate *interpolate )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->get_window_size );
	return( class->get_window_size( interpolate ) );
}

/* VipsInterpolateNearest class
 */

#ifdef DEBUG
static void
vips_interpolate_nearest_finalize( GObject *gobject )
{
	printf( "vips_interpolate_nearest_finalize: " );
	vips_object_print( VIPS_OBJECT( gobject ) );

	G_OBJECT_CLASS( vips_interpolate_nearest_parent_class )->
		finalize( gobject );
}
#endif /*DEBUG*/

static void
vips_interpolate_nearest_interpolate( VipsInterpolate *interpolate, 
	REGION *out, REGION *in, 
	int out_x, int out_y, double in_x, double in_y )
{
	/* Pel size and line size.
	 */
	const int ps = IM_IMAGE_SIZEOF_PEL( in->im );
	int z;

	PEL *q = (PEL *) IM_REGION_ADDR( out, out_x, out_y ); 

	/* Subtract 0.5 to centre the nearest.
	 */
	const double cx = in_x - 0.5;
	const double cy = in_y - 0.5;

	/* Top left corner we interpolate from.
	 */
	const int xi = FLOOR( cx );
	const int yi = FLOOR( cy );

	const PEL *p = (PEL *) IM_REGION_ADDR( in, xi, yi ); 

	for( z = 0; z < ps; z++ )
		q[z] = p[z];
}

static void
vips_interpolate_nearest_class_init( VipsInterpolateNearestClass *class )
{
#ifdef DEBUG
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
#endif /*DEBUG*/
	VipsInterpolateClass *interpolate_class = 
		VIPS_INTERPOLATE_CLASS( class );

	vips_interpolate_nearest_parent_class = 
		g_type_class_peek_parent( class );

#ifdef DEBUG
	gobject_class->finalize = vips_interpolate_nearest_finalize;
#endif /*DEBUG*/
	interpolate_class->interpolate = vips_interpolate_nearest_interpolate;
	interpolate_class->window_size = 1;
}

static void
vips_interpolate_nearest_init( VipsInterpolateNearest *nearest )
{
#ifdef DEBUG
	printf( "vips_interpolate_nearest_init: " );
	vips_object_print( VIPS_OBJECT( nearest ) );
#endif /*DEBUG*/
}

GType
vips_interpolate_nearest_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		static const GTypeInfo info = {
			sizeof( VipsObjectClass ),
			NULL,           /* base_init */
			NULL,           /* base_finalize */
			(GClassInitFunc) vips_interpolate_nearest_class_init,
			NULL,           /* class_finalize */
			NULL,           /* class_data */
			sizeof( VipsObject ),
			32,             /* n_preallocs */
			(GInstanceInitFunc) vips_interpolate_nearest_init,
		};

		type = g_type_register_static( VIPS_TYPE_INTERPOLATE, 
			"VipsInterpolateNearest", &info, 0 );
	}

	return( type );
}

VipsInterpolateNearest *
vips_interpolate_nearest_new( void )
{
	return( g_object_new( VIPS_TYPE_INTERPOLATE_NEAREST, NULL ) );
}

/* Convenience: return a static nearest you don't need to free.
 */
VipsInterpolate *
vips_interpolate_nearest_static( void )
{
	static VipsInterpolate *interpolate = NULL;

	if( !interpolate )
		interpolate = 
			VIPS_INTERPOLATE( vips_interpolate_nearest_new() );

	return( interpolate );
}

/* VipsInterpolateBilinear class
 */

#ifdef DEBUG
static void
vips_interpolate_bilinear_finalize( GObject *gobject )
{
	printf( "vips_interpolate_bilinear_finalize: " );
	vips_object_print( VIPS_OBJECT( gobject ) );

	G_OBJECT_CLASS( vips_interpolate_bilinear_parent_class )->
		finalize( gobject );
}
#endif /*DEBUG*/

/* Interpolate a section ... int8/16 types.
 */
#define BILINEAR_INT( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
 	\
	const int m1 = class->matrix_int[xi][0]; \
	const int m2 = class->matrix_int[xi][1]; \
	const int m3 = class->matrix_int[yi][0]; \
	const int m4 = class->matrix_int[yi][1]; \
	\
	const int c1 = (m3 * m1) >> VIPS_INTERPOLATE_SHIFT; \
	const int c2 = (m3 * m2) >> VIPS_INTERPOLATE_SHIFT; \
	const int c3 = (m4 * m1) >> VIPS_INTERPOLATE_SHIFT; \
	const int c4 = (m4 * m2) >> VIPS_INTERPOLATE_SHIFT; \
 	\
	/* var points to \
	 * p1  (x_int,   y_int) \
	 * p2  (x_int+1, y_int) \
	 * p3  (x_int,   y_int+1) \
	 * p4  (x_int+1, y_int+1) \
	 */ \
	const TYPE *tp1 = (TYPE *) p1; \
	const TYPE *tp2 = (TYPE *) p2; \
	const TYPE *tp3 = (TYPE *) p3; \
	const TYPE *tp4 = (TYPE *) p4; \
	\
	/* Interpolate each band. \
	 */ \
	for( z = 0; z < b; z++ ) \
		tq[z] = (c1 * tp1[z] + c2 * tp2[z] + \
			 c3 * tp3[z] + c4 * tp4[z]) >> VIPS_INTERPOLATE_SHIFT; \
}

/* Interpolate a pel ... int32 and float types.
 */
#define BILINEAR_FLOAT( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
 	\
	const double m1 = class->matrix_double[xi][0]; \
	const double m2 = class->matrix_double[xi][1]; \
	const double m3 = class->matrix_double[yi][0]; \
	const double m4 = class->matrix_double[yi][1]; \
	\
	const double c1 = m3 * m1; \
	const double c2 = m3 * m2; \
	const double c3 = m4 * m1; \
	const double c4 = m4 * m2; \
	\
	/* var points to \
	 * p1  (x_int,   y_int) \
	 * p2  (x_int+1, y_int) \
	 * p3  (x_int,   y_int+1) \
	 * p4  (x_int+1, y_int+1) \
	 */ \
	const TYPE *tp1 = (TYPE *) p1; \
	const TYPE *tp2 = (TYPE *) p2; \
	const TYPE *tp3 = (TYPE *) p3; \
	const TYPE *tp4 = (TYPE *) p4; \
	\
	/* Interpolate each band. \
	 */ \
	for( z = 0; z < b; z++ ) \
		tq[z] = c1 * tp1[z] + c2 * tp2[z] + \
			c3 * tp3[z] + c4 * tp4[z]; \
}

/* Interpolate a pel ... don't use the pre-calcuated matricies.
 */
#define BILINEAR_SLOW( TYPE ) { \
	TYPE *tq = (TYPE *) q; \
 	\
	/* var points to \
	 * p1  (x_int,   y_int) \
	 * p2  (x_int+1, y_int) \
	 * p3  (x_int,   y_int+1) \
	 * p4  (x_int+1, y_int+1) \
	 */ \
	const TYPE *tp1 = (TYPE *) p1; \
	const TYPE *tp2 = (TYPE *) p2; \
	const TYPE *tp3 = (TYPE *) p3; \
	const TYPE *tp4 = (TYPE *) p4; \
	\
	/* Interpolate each band. \
	 */ \
	for( z = 0; z < b; z++ ) \
		tq[z] = c1 * tp1[z] + c2 * tp2[z] + \
			c3 * tp3[z] + c4 * tp4[z]; \
}

/* Expand for band types. with a fixed-point interpolator and a float
 * interpolator.
 */
#define SWITCH_INTERPOLATE( FMT, INT, FLOAT ) { \
	switch( (FMT) ) { \
	case IM_BANDFMT_UCHAR:	INT( unsigned char ); break; \
	case IM_BANDFMT_CHAR: 	INT( char ); break;  \
	case IM_BANDFMT_USHORT: INT( unsigned short ); break;  \
	case IM_BANDFMT_SHORT: 	INT( short ); break;  \
	case IM_BANDFMT_UINT: 	FLOAT( unsigned int ); break;  \
	case IM_BANDFMT_INT: 	FLOAT( int );  break;  \
	case IM_BANDFMT_FLOAT: 	FLOAT( float ); break;  \
	case IM_BANDFMT_DOUBLE:	FLOAT( double ); break;  \
	default: \
		g_assert( FALSE ); \
	} \
}

static void
vips_interpolate_bilinear_interpolate( VipsInterpolate *interpolate, 
	REGION *out, REGION *in, 
	int out_x, int out_y, double in_x, double in_y )
{
	VipsInterpolateBilinear *bilinear = 
		VIPS_INTERPOLATE_BILINEAR( interpolate );
	VipsInterpolateBilinearClass *class = 
		VIPS_INTERPOLATE_BILINEAR_GET_CLASS( interpolate );

	/* Pel size and line size.
	 */
	const int ps = IM_IMAGE_SIZEOF_PEL( in->im );
	const int ls = IM_REGION_LSKIP( in ); 
	const int b = in->im->Bands; 
	int z;

	PEL *q = (PEL *) IM_REGION_ADDR( out, out_x, out_y ); 

	if( bilinear->slow ) {
		/* Subtract 0.5 to centre the bilinear.
		 */
		const double cx = in_x - 0.5;
		const double cy = in_y - 0.5;

		/* Top left corner we interpolate from.
		 */
		const int xi = FLOOR( cx );
		const int yi = FLOOR( cy );

		/* Fractional part.
		 */
		const double X = cx - xi;
		const double Y = cy - yi;
		
		/* Residual.
		 */
		const double Xd = 1.0 - X;	
		const double Yd = 1.0 - Y;

		/* Weights.
		 */
		const double c1 = Xd * Yd;
		const double c2 = X * Yd;
		const double c3 = X * Y;
		const double c4 = Xd * Y;

		/* var points to 
		 * p1  (x_int,   y_int) 
		 * p2  (x_int+1, y_int) 
		 * p3  (x_int,   y_int+1) 
		 * p4  (x_int+1, y_int+1) 
		 */ 
		const PEL *p1 = (PEL *) IM_REGION_ADDR( in, xi, yi ); 
		const PEL *p2 = p1 + ps;
		const PEL *p3 = p1 + ls; 
		const PEL *p4 = p1 + ls + ps; 

		SWITCH_INTERPOLATE( in->im->BandFmt, 
			BILINEAR_SLOW, BILINEAR_SLOW );
	}
	else {
		/* Subtract 0.5 to centre the bilinear.
		 */
		const double cx = in_x - 0.5;
		const double cy = in_y - 0.5;

		/* Now go to scaled int. 
		 */
		const double sx = cx * VIPS_TRANSFORM_SCALE;
		const double sy = cy * VIPS_TRANSFORM_SCALE;
		const int sxi = FLOOR( sx );
		const int syi = FLOOR( sy );

		/* Get index into interpolation table and unscaled integer 
		 * position.
		 */
		const int xi = sxi & (VIPS_TRANSFORM_SCALE - 1);
		const int yi = syi & (VIPS_TRANSFORM_SCALE - 1);
		const int in_x_int = sxi >> VIPS_TRANSFORM_SHIFT;
		const int in_y_int = syi >> VIPS_TRANSFORM_SHIFT;

		/* var points to 
		 * p1  (x_int,   y_int) 
		 * p2  (x_int+1, y_int) 
		 * p3  (x_int,   y_int+1) 
		 * p4  (x_int+1, y_int+1) 
		 */ 
		const PEL *p1 = (PEL *) 
			IM_REGION_ADDR( in, in_x_int, in_y_int ); 
		const PEL *p2 = p1 + ps;
		const PEL *p3 = p1 + ls; 
		const PEL *p4 = p1 + ls + ps; 

		SWITCH_INTERPOLATE( in->im->BandFmt, 
			BILINEAR_INT, BILINEAR_FLOAT );
	}
}

static void
vips_interpolate_bilinear_class_init( VipsInterpolateBilinearClass *class )
{
#ifdef DEBUG
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
#endif /*DEBUG*/
	VipsInterpolateClass *interpolate_class = 
		(VipsInterpolateClass *) class;
	int x;

	vips_interpolate_bilinear_parent_class = 
		g_type_class_peek_parent( class );

#ifdef DEBUG
	gobject_class->finalize = vips_interpolate_bilinear_finalize;
#endif /*DEBUG*/
	interpolate_class->interpolate = vips_interpolate_bilinear_interpolate;
	interpolate_class->window_size = 2;

	/* Calculate the interpolation matricies.
	 */
	for( x = 0; x < VIPS_TRANSFORM_SCALE + 1; x++ ) {
		const double c1 = (double) x / VIPS_TRANSFORM_SCALE;
		const double c2 = 1.0 - c1;	

		class->matrix_double[x][0] = c1;
		class->matrix_double[x][1] = c2;

		class->matrix_int[x][0] = c1 * VIPS_INTERPOLATE_SCALE;
		class->matrix_int[x][1] = c2 * VIPS_INTERPOLATE_SCALE;
	}
}

static void
vips_interpolate_bilinear_init( VipsInterpolateBilinear *bilinear )
{
#ifdef DEBUG
	printf( "vips_interpolate_bilinear_init: " );
	vips_object_print( VIPS_OBJECT( bilinear ) );
#endif /*DEBUG*/

	bilinear->slow = FALSE;
}

GType
vips_interpolate_bilinear_get_type( void )
{
	static GType type = 0;

	if( !type ) {
		static const GTypeInfo info = {
			sizeof( VipsObjectClass ),
			NULL,           /* base_init */
			NULL,           /* base_finalize */
			(GClassInitFunc) vips_interpolate_bilinear_class_init,
			NULL,           /* class_finalize */
			NULL,           /* class_data */
			sizeof( VipsObject ),
			32,             /* n_preallocs */
			(GInstanceInitFunc) vips_interpolate_bilinear_init,
		};

		type = g_type_register_static( VIPS_TYPE_INTERPOLATE, 
			"VipsInterpolateBilinear", &info, 0 );
	}

	return( type );
}

void
vips_interpolate_bilinear_set_slow( VipsInterpolateBilinear *bilinear, 
	gboolean slow )
{
	bilinear->slow = slow;
}

VipsInterpolateBilinear *
vips_interpolate_bilinear_new( void )
{
	return( g_object_new( VIPS_TYPE_INTERPOLATE_BILINEAR, NULL ) );
}


/* Convenience: return a static bilinear you don't need to free.
 */
VipsInterpolate *
vips_interpolate_bilinear_static( void )
{
	static VipsInterpolate *interpolate = NULL;

	if( !interpolate )
		interpolate = 
			VIPS_INTERPOLATE( vips_interpolate_bilinear_new() );

	return( interpolate );
}

