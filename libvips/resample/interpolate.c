/* vipsinterpolate ... abstract base class for various interpolators
 *
 * J. Cupitt, 15/10/08
 *
 * 12/8/10
 * 	- revise window_size / window_offset stuff again: window_offset now
 * 	  defaults to (window_size / 2 - 1), so for a 4x4 stencil (eg.
 * 	  bicubic) we have an offset of 1
 * 	- tiny speedups
 * 7/1/11
 * 	- don't use tables for bilinear on float data for a small speedup
 * 	  (thanks Nicolas Robidoux)
 * 12/1/11
 * 	- faster, more accuarate uchar bilinear (thanks Nicolas)
 * 2/2/11
 * 	- gtk-doc
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

#include <vips/vips.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: interpolate
 * @short_description: various interpolators: nearest, bilinear, bicubic, and
 * some non-linear
 * @stability: Stable
 * @include: vips/vips.h
 *
 * A number of image interpolators.
 */

G_DEFINE_ABSTRACT_TYPE( VipsInterpolate, vips_interpolate, VIPS_TYPE_OBJECT );

/**
 * VipsInterpolateMethod:
 * @interpolate: the interpolator
 * @out: write the interpolated pixel here
 * @in: read source pixels from here
 * @x: interpolate value at this position
 * @y: interpolate value at this position
 *
 * An interpolation function. It should read source pixels from @in with
 * IM_REGION_ADDR(), it can look left and up from (x, y) by @window_offset
 * pixels and it can access pixels in a window of size @window_size.
 *
 * The interpolated value should be written to the pixel pointed to by @out.
 *
 * See also: #VipsInterpolateClass.
 */

/**
 * VipsInterpolateClass:
 * @interpolate: the interpolation method
 * @get_window_size: return the size of the window needed by this method
 * @window_size: or just set this for a constant window size
 * @get_window_offset: return the window offset for this method
 * @window_offset: or just set this for a constant window offset
 *
 * The abstract base class for the various VIPS interpolation functions. 
 * Use "vips --list classes" to see all the interpolators available.
 *
 * An interpolator consists of a function to perform the interpolation, plus
 * some extra data fields which tell vips how to call the function and what
 * data it needs.
 *
 * @window_size is the size of the window that the interpolator needs. For
 * example, a bicubic interpolator needs to see a window of 4x4 pixels to be
 * able to interpolate a value. 
 *
 * You can either have a function in @get_window_size which returns the window
 * that a specific interpolator needs, or you can leave @get_window_size %NULL
 * and set a constant value in @window_size.
 *
 * @window_offset is how much to offset the window up and left of (x, y). For
 * example, a bicubic interpolator will want a @window_offset of 1.
 *
 * You can either have a function in @get_window_offset which returns the
 * offset that a specific interpolator needs, or you can leave
 * @get_window_offset %NULL and set a constant value in @window_offset.
 *
 * You also need to set @nickname and @description in #VipsObject.
 *
 * See also: #VipsInterpolateMethod, #VipsObject, 
 * vips_interpolate_bilinear_static().
 */

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

static int
vips_interpolate_real_get_window_offset( VipsInterpolate *interpolate )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

 	/* Default to half window size - 1. For example, bicubic is a 4x4
	 * stencil and needs an offset of 1.
 	 */
	if( class->window_offset != -1 )
		return( class->window_offset );
	else {
		int window_size = 
			vips_interpolate_get_window_size( interpolate );

		/* Don't go -ve, of course, for window_size 1.
		 */
		return( IM_MAX( 0, window_size / 2 - 1 ) );
	}
}

static void
vips_interpolate_class_init( VipsInterpolateClass *class )
{
#ifdef DEBUG
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
#endif /*DEBUG*/

#ifdef DEBUG
	gobject_class->finalize = vips_interpolate_finalize;
#endif /*DEBUG*/
	class->interpolate = NULL;
	class->get_window_size = vips_interpolate_real_get_window_size;
	class->get_window_offset = vips_interpolate_real_get_window_offset;
	class->window_size = -1;
	class->window_offset = -1;
}

static void
vips_interpolate_init( VipsInterpolate *interpolate )
{
#ifdef DEBUG
	printf( "vips_interpolate_init: " );
	vips_object_print( VIPS_OBJECT( interpolate ) );
#endif /*DEBUG*/
}

/** 
 * vips_interpolate:
 * @interpolate: interpolator to use
 * @out: write result here
 * @in: read source data from here
 * @x: interpolate value at this position
 * @y: interpolate value at this position
 *
 * Look up the @interpolate method in the class and call it. Use
 * vips_interpolate_get_method() to get a direct pointer to the function and
 * avoid the lookup overhead.
 *
 * You need to set @in and @out up correctly.
 */
void
vips_interpolate( VipsInterpolate *interpolate,
	PEL *out, REGION *in, double x, double y )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->interpolate );

	class->interpolate( interpolate, out, in, x, y );
}

/** 
 * vips_interpolate_get_method:
 * @interpolate: interpolator to use
 *
 * Look up the @interpolate method in the class and return it. Use this
 * instead of vips_interpolate() to cache method dispatch.
 *
 * Returns: a pointer to the interpolation function
 */
VipsInterpolateMethod
vips_interpolate_get_method( VipsInterpolate *interpolate )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->interpolate );

	return( class->interpolate );
}

/** 
 * vips_interpolate_get_window_size:
 * @interpolate: interpolator to use
 *
 * Look up an interpolators desired window size. 
 *
 * Returns: the interpolators required window size
 */
int
vips_interpolate_get_window_size( VipsInterpolate *interpolate )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->get_window_size );

	return( class->get_window_size( interpolate ) );
}

/** 
 * vips_interpolate_get_window_offset:
 * @interpolate: interpolator to use
 *
 * Look up an interpolators desired window offset. 
 *
 * Returns: the interpolators required window offset
 */
int
vips_interpolate_get_window_offset( VipsInterpolate *interpolate )
{
	VipsInterpolateClass *class = VIPS_INTERPOLATE_GET_CLASS( interpolate );

	g_assert( class->get_window_offset );

	return( class->get_window_offset( interpolate ) );
}

/**
 * VIPS_TRANSFORM_SHIFT:
 *
 * Many of the vips interpolators use fixed-point arithmetic for coordinate
 * calculation. This is how many bits of precision they use.
 */

/**
 * VIPS_TRANSFORM_SCALE:
 *
 * #VIPS_TRANSFORM_SHIFT as a multiplicative constant. 
 */

/**
 * VIPS_INTERPOLATE_SHIFT:
 *
 * Many of the vips interpolators use fixed-point arithmetic for value
 * calcualtion. This is how many bits of precision they use.
 */

/**
 * VIPS_INTERPOLATE_SCALE:
 *
 * #VIPS_INTERPOLATE_SHIFT as a multiplicative constant. 
 */

/* VipsInterpolateNearest class
 */

#define VIPS_TYPE_INTERPOLATE_NEAREST (vips_interpolate_nearest_get_type())
#define VIPS_INTERPOLATE_NEAREST( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_NEAREST, VipsInterpolateNearest ))
#define VIPS_INTERPOLATE_NEAREST_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_NEAREST, VipsInterpolateNearestClass))
#define VIPS_IS_INTERPOLATE_NEAREST( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_NEAREST ))
#define VIPS_IS_INTERPOLATE_NEAREST_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_NEAREST ))
#define VIPS_INTERPOLATE_NEAREST_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_NEAREST, VipsInterpolateNearestClass ))

/* No new members.
 */
typedef VipsInterpolate VipsInterpolateNearest;
typedef VipsInterpolateClass VipsInterpolateNearestClass;

G_DEFINE_TYPE( VipsInterpolateNearest, vips_interpolate_nearest,
	VIPS_TYPE_INTERPOLATE );

static void
vips_interpolate_nearest_interpolate( VipsInterpolate *interpolate,
	PEL *out, REGION *in, double x, double y )
{
	/* Pel size and line size.
	 */
	const int ps = IM_IMAGE_SIZEOF_PEL( in->im );

	/* Top left corner we interpolate from. We know x/y are always
	 * positive, so we can just (int) them.
	 */
	const int xi = (int) x;
	const int yi = (int) y;

	const PEL *p = (PEL *) IM_REGION_ADDR( in, xi, yi );

	int z;

	for( z = 0; z < ps; z++ )
		out[z] = p[z];
}

static void
vips_interpolate_nearest_class_init( VipsInterpolateNearestClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsInterpolateClass *interpolate_class =
		VIPS_INTERPOLATE_CLASS( class );

	object_class->nickname = "nearest";
	object_class->description = _( "Nearest-neighbour interpolation" );

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

VipsInterpolate *
vips_interpolate_nearest_new( void )
{

	return( VIPS_INTERPOLATE( vips_object_new(
		VIPS_TYPE_INTERPOLATE_NEAREST, NULL, NULL, NULL ) ) );
}

/**
 * vips_interpolate_nearest_static:
 *
 * A convenience function that returns a nearest-neighbour interpolator you 
 * don't need to free.
 *
 * Returns: a nearest-neighbour interpolator
 */
VipsInterpolate *
vips_interpolate_nearest_static( void )
{
	static VipsInterpolate *interpolate = NULL;

	if( !interpolate )
		interpolate = vips_interpolate_nearest_new();

	return( interpolate );
}

/* VipsInterpolateBilinear class
 */

#define VIPS_TYPE_INTERPOLATE_BILINEAR (vips_interpolate_bilinear_get_type())
#define VIPS_INTERPOLATE_BILINEAR( obj ) \
	(G_TYPE_CHECK_INSTANCE_CAST( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR, VipsInterpolateBilinear ))
#define VIPS_INTERPOLATE_BILINEAR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_CAST( (klass), \
	VIPS_TYPE_INTERPOLATE_BILINEAR, VipsInterpolateBilinearClass))
#define VIPS_IS_INTERPOLATE_BILINEAR( obj ) \
	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), VIPS_TYPE_INTERPOLATE_BILINEAR ))
#define VIPS_IS_INTERPOLATE_BILINEAR_CLASS( klass ) \
	(G_TYPE_CHECK_CLASS_TYPE( (klass), VIPS_TYPE_INTERPOLATE_BILINEAR ))
#define VIPS_INTERPOLATE_BILINEAR_GET_CLASS( obj ) \
	(G_TYPE_INSTANCE_GET_CLASS( (obj), \
	VIPS_TYPE_INTERPOLATE_BILINEAR, VipsInterpolateBilinearClass ))

typedef VipsInterpolate VipsInterpolateBilinear;
typedef VipsInterpolateClass VipsInterpolateBilinearClass;

G_DEFINE_TYPE( VipsInterpolateBilinear, vips_interpolate_bilinear,
	VIPS_TYPE_INTERPOLATE );

/* in this class, name vars in the 2x2 grid as eg.
 * p1  p2
 * p3  p4
 */

/* Fixed-point arithmetic, no tables.
 */
#define BILINEAR_INT( TYPE ) { \
	TYPE *tq = (TYPE *) out; \
	\
	const int X = (x - ix) * VIPS_INTERPOLATE_SCALE; \
	const int Y = (iy - y) * VIPS_INTERPOLATE_SCALE; \
	\
	const TYPE *tp1 = (TYPE *) p1; \
	const TYPE *tp2 = (TYPE *) p2; \
	const TYPE *tp3 = (TYPE *) p3; \
	const TYPE *tp4 = (TYPE *) p4; \
	\
	for( z = 0; z < b; z++ ) { \
		const int top = tp1[z] + \
			((X * (tp2[z] - tp1[z])) >> VIPS_INTERPOLATE_SHIFT); \
		const int bot = tp3[z] + \
			((X * (tp4[z] - tp3[z])) >> VIPS_INTERPOLATE_SHIFT); \
		\
		tq[z] = top - ((Y * (bot - top)) >> VIPS_INTERPOLATE_SHIFT); \
	} \
}

/* Interpolate a pel ... int32 and float types, no tables, float 
 * arithmetic.
 */
#define BILINEAR_FLOAT( TYPE ) { \
	TYPE *tq = (TYPE *) out; \
	\
	float Y  = y - iy; \
	float X  = x - ix; \
        \
	float Yd = 1.0f - Y; \
        \
	float c4 = Y  * X; \
	float c2 = Yd * X; \
	float c3 = Y  - c4; \
	float c1 = Yd - c2; \
 	\
	const TYPE *tp1 = (TYPE *) p1; \
	const TYPE *tp2 = (TYPE *) p2; \
	const TYPE *tp3 = (TYPE *) p3; \
	const TYPE *tp4 = (TYPE *) p4; \
	\
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
	PEL *out, REGION *in, double x, double y )
{
	/* Pel size and line size.
	 */
	const int ps = IM_IMAGE_SIZEOF_PEL( in->im );
	const int ls = IM_REGION_LSKIP( in );
	const int b = in->im->Bands;

	const int ix = (int) x;
	const int iy = (int) y;

	const PEL *p1 = (PEL *) IM_REGION_ADDR( in, ix, iy );
	const PEL *p2 = p1 + ps;
	const PEL *p3 = p1 + ls;
	const PEL *p4 = p3 + ps;

	int z;

	SWITCH_INTERPOLATE( in->im->BandFmt,
		BILINEAR_INT, BILINEAR_FLOAT );
}

static void
vips_interpolate_bilinear_class_init( VipsInterpolateBilinearClass *class )
{
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsInterpolateClass *interpolate_class =
		(VipsInterpolateClass *) class;

	object_class->nickname = "bilinear";
	object_class->description = _( "Bilinear interpolation" );

	interpolate_class->interpolate = vips_interpolate_bilinear_interpolate;
	interpolate_class->window_size = 2;
}

static void
vips_interpolate_bilinear_init( VipsInterpolateBilinear *bilinear )
{
#ifdef DEBUG
	printf( "vips_interpolate_bilinear_init: " );
	vips_object_print( VIPS_OBJECT( bilinear ) );
#endif /*DEBUG*/

}

VipsInterpolate *
vips_interpolate_bilinear_new( void )
{
	return( VIPS_INTERPOLATE( vips_object_new(
		VIPS_TYPE_INTERPOLATE_BILINEAR, NULL, NULL, NULL ) ) );
}

/**
 * vips_interpolate_bilinear_static:
 *
 * A convenience function that returns a bilinear interpolator you 
 * don't need to free.
 *
 * Returns: a bilinear interpolator
 */
VipsInterpolate *
vips_interpolate_bilinear_static( void )
{
	static VipsInterpolate *interpolate = NULL;

	if( !interpolate )
		interpolate = vips_interpolate_bilinear_new();

	return( interpolate );
}

/* Called on startup: register the base vips interpolators.
 */
void
vips__interpolate_init( void )
{
	extern GType vips_interpolate_bicubic_get_type( void );
	extern GType vips_interpolate_lbb_get_type( void );
	extern GType vips_interpolate_nohalo_get_type( void );
	extern GType vips_interpolate_vsqbs_get_type( void );

	vips_interpolate_nearest_get_type();
	vips_interpolate_bilinear_get_type();

#ifdef ENABLE_CXX
	vips_interpolate_bicubic_get_type();
	vips_interpolate_lbb_get_type();
	vips_interpolate_nohalo_get_type();
	vips_interpolate_vsqbs_get_type();
#endif /*ENABLE_CXX*/
}

/**
 * vips_interpolate_new:
 * @nickname: nickname for interpolator
 *
 * Look up an interpolator from a nickname and make one. You need to free the
 * result with g_object_unref() when you're done with it.
 *
 * See also: vips_type_find().
 *
 * Returns: an interpolator, or %NULL on error.
 */
VipsInterpolate *
vips_interpolate_new( const char *nickname )
{
	GType type;

	if( !(type = vips_type_find( "VipsInterpolate", nickname )) )
		return( NULL );

	return( VIPS_INTERPOLATE( vips_object_new( type, NULL, NULL, NULL ) ) );
}
