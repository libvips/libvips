/* map though a LUT
 *
 * Modified:
 * 18/6/93 JC
 *	- oops! im_incheck() added for LUT image
 * 	- some ANSIfication
 * 15/7/93 JC
 *	- adapted for partial v2
 *	- ANSIfied
 *	- now does complex LUTs too
 * 10/3/94 JC
 *	- more helpful error messages, slight reformatting
 * 24/8/94 JC
 *	- now allows non-uchar image input
 * 7/10/94 JC
 *	- uses im_malloc(), IM_NEW() etc.
 * 13/3/95 JC
 *	- now takes a private copy of LUT, so user can im_close() LUT image
 *	  after im_maplut() without fear of coredumps
 * 23/6/95 JC
 *	- lut may now have many bands if image has just one band
 * 3/3/01 JC
 *	- small speed ups
 * 30/6/04
 *	- heh, 1 band image + 3 band lut + >8bit output has been broken for 9
 *	  years :-)
 * 7/11/07
 * 	- new eval start/end system
 * 25/3/10
 * 	- gtkdoc
 * 	- small cleanups
 * 5/7/13
 * 	- convert to a class
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
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

#include "phistogram.h"

typedef struct _VipsMaplut {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsImage *lut;

	int fmt;		/* LUT image BandFmt */
	int nb;			/* Number of bands in lut */
	int es;			/* VIPS_IMAGE_SIZEOF_ELEMENT() for lut image */
	int sz;			/* Number of elements in minor dimension */
	int clp;		/* Value we clip against */
	VipsPel **table;	/* Lut converted to 2d array */
	int overflow;		/* Number of overflows for non-uchar lut */

} VipsMaplut;

typedef VipsOperationClass VipsMaplutClass;

G_DEFINE_TYPE( VipsMaplut, vips_maplut, VIPS_TYPE_OPERATION );

static void
vips_maplut_preeval( VipsImage *image, VipsProgress *progress, 
	VipsMaplut *maplut )
{
	maplut->overflow = 0;
}

static void
vips_maplut_posteval( VipsImage *image, VipsProgress *progress, 
	VipsMaplut *maplut )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( maplut );

	if( maplut->overflow )
		vips_warn( class->nickname, 
			_( "%d overflows detected" ), maplut->overflow );
}

/* Our sequence value: the region this sequence is using, and local stats.
 */
typedef struct {
	VipsRegion *ir;		/* Input region */
	int overflow;		/* Number of overflows */
} VipsMaplutSequence;

/* Our start function.
 */
static void *
vips_maplut_start( VipsImage *out, void *a, void *b )
{
	VipsImage *in = (VipsImage *) a;
	VipsMaplutSequence *seq;

	if( !(seq = VIPS_NEW( out, VipsMaplutSequence )) )
		 return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->overflow = 0;

	if( !(seq->ir = vips_region_new( in )) ) 
		return( NULL );

	return( seq );
}

/* Map through n non-complex luts.
 */
#define loop( OUT ) { \
	int b = st->nb; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
			OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
			OUT *tlut = (OUT *) st->table[z]; \
			\
			for( x = z; x < ne; x += b ) \
				q[x] = tlut[p[x]]; \
		} \
	} \
}

/* Map through n complex luts.
 */
#define loopc( OUT ) { \
	int b = in->Bands; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			VipsPel *p = VIPS_REGION_ADDR( ir, le, y ) + z; \
			OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ) + z * 2; \
			OUT *tlut = (OUT *) st->table[z]; \
			\
			for( x = 0; x < ne; x += b ) { \
				int n = p[x] * 2; \
				\
				q[0] = tlut[n]; \
				q[1] = tlut[n + 1]; \
				q += b * 2; \
			} \
		} \
	} \
}

#define loopg( IN, OUT ) { \
	int b = st->nb; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
			OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
			OUT *tlut = (OUT *) st->table[z]; \
			\
			for( x = z; x < ne; x += b ) { \
				int index = p[x]; \
				\
				if( index > st->clp ) { \
					index = st->clp; \
					seq->overflow++; \
				} \
				\
				q[x] = tlut[index]; \
			} \
		} \
	} \
}

#define loopcg( IN, OUT ) { \
	int b = in->Bands; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ) + z; \
			OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ) + z * 2; \
			OUT *tlut = (OUT *) st->table[z]; \
			\
			for( x = 0; x < ne; x += b ) { \
				int index = p[x]; \
				\
				if( index > st->clp ) { \
					index = st->clp; \
					seq->overflow++; \
				} \
				\
				q[0] = tlut[index * 2]; \
				q[1] = tlut[index * 2 + 1]; \
				\
				q += b * 2; \
			} \
		} \
	} \
}

/* Map image through one non-complex lut.
 */
#define loop1( OUT ) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) \
			q[x] = tlut[p[x]]; \
	} \
}

/* Map image through one complex lut.
 */
#define loop1c( OUT ) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) { \
			int n = p[x] * 2; \
			\
			q[0] = tlut[n]; \
			q[1] = tlut[n + 1]; \
			q += 2; \
		} \
	} \
}

/* As above, but the input image may be any unsigned integer type. We have to
 * index the lut carefully, and record the number of overflows we detect.
 */
#define loop1g( IN, OUT ) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) { \
			int index = p[x]; \
			\
			if( index > st->clp ) { \
				index = st->clp; \
				seq->overflow++; \
			} \
			\
			q[x] = tlut[index]; \
		} \
	} \
}

#define loop1cg( IN, OUT ) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) { \
			int index = p[x]; \
			\
			if( index > st->clp ) { \
				index = st->clp; \
				seq->overflow++; \
			} \
			\
			q[0] = tlut[index * 2]; \
			q[1] = tlut[index * 2 + 1]; \
			q += 2; \
		} \
	} \
}

/* Map 1-band image through a many-band non-complex lut.
 */
#define loop1m( OUT ) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( i = 0, x = 0; x < np; x++ ) { \
			int n = p[x]; \
			\
			for( z = 0; z < st->nb; z++, i++ ) \
				q[i] = tlut[z][n]; \
		} \
	} \
}

/* Map 1-band image through many-band complex lut.
 */
#define loop1cm( OUT ) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < np; x++ ) { \
			int n = p[x] * 2; \
			\
			for( z = 0; z < st->nb; z++ ) { \
				q[0] = tlut[z][n]; \
				q[1] = tlut[z][n+1]; \
				q += 2; \
			} \
		} \
	} \
}

/* Map 1-band uint or ushort image through a many-band non-complex LUT.
 */
#define loop1gm( IN, OUT ) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		\
		for( i = 0, x = 0; x < np; x++ ) { \
			int n = p[x]; \
			\
			if( n > st->clp ) { \
				n = st->clp; \
				seq->overflow++; \
			} \
			\
			for( z = 0; z < st->nb; z++, i++ ) \
				q[i] = tlut[z][n]; \
		} \
	} \
}

/* Map 1-band uint or ushort image through a many-band complex LUT.
 */
#define loop1cgm( IN, OUT ) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		\
		for( x = 0; x < np; x++ ) { \
			int n = p[x]; \
			\
			if( n > st->clp ) { \
				n = st->clp; \
				seq->overflow++; \
			} \
			\
			for( z = 0; z < st->nb; z++ ) { \
				q[0] = tlut[z][n * 2]; \
				q[1] = tlut[z][n * 2 + 1]; \
				q += 2; \
			} \
		} \
	} \
}

/* Switch for input types. Has to be uint type!
 */
#define inner_switch( UCHAR, GEN, OUT ) \
	switch( ir->im->BandFmt ) { \
	case VIPS_FORMAT_UCHAR:		UCHAR( OUT ); break; \
	case VIPS_FORMAT_USHORT:	GEN( unsigned short, OUT ); break; \
	case VIPS_FORMAT_UINT:		GEN( unsigned int, OUT ); break; \
	default: \
		g_assert( 0 ); \
	}

/* Switch for LUT types. One function for non-complex images, a
 * variant for complex ones. Another pair as well, in case the input is not
 * uchar.
 */
#define outer_switch( UCHAR_F, UCHAR_FC, GEN_F, GEN_FC ) \
	switch( st->fmt ) { \
	case VIPS_FORMAT_UCHAR:		inner_switch( UCHAR_F, GEN_F, \
						unsigned char ); break; \
	case VIPS_FORMAT_CHAR:		inner_switch( UCHAR_F, GEN_F, \
						char ); break; \
	case VIPS_FORMAT_USHORT:	inner_switch( UCHAR_F, GEN_F, \
						unsigned short ); break; \
	case VIPS_FORMAT_SHORT:		inner_switch( UCHAR_F, GEN_F, \
						short ); break; \
	case VIPS_FORMAT_UINT:		inner_switch( UCHAR_F, GEN_F, \
						unsigned int ); break; \
	case VIPS_FORMAT_INT:		inner_switch( UCHAR_F, GEN_F, \
						int ); break; \
	case VIPS_FORMAT_FLOAT:		inner_switch( UCHAR_F, GEN_F, \
						float ); break; \
	case VIPS_FORMAT_DOUBLE:	inner_switch( UCHAR_F, GEN_F, \
						double ); break; \
	case VIPS_FORMAT_COMPLEX:	inner_switch( UCHAR_FC, GEN_FC, \
						float ); break; \
	case VIPS_FORMAT_DPCOMPLEX:	inner_switch( UCHAR_FC, GEN_FC, \
						double ); break; \
	default: \
		g_assert( 0 ); \
	}

/* Do a map.
 */
static int 
vips_maplut_gen( VipsRegion *or, void *vseq, void *a, void *b, 
	gboolean *stop )
{
	VipsMaplutSequence *seq = (VipsMaplutSequence *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsMaplut *st = (VipsMaplut *) b;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM(r);
	int np = r->width;			/* Pels across region */
	int ne = VIPS_REGION_N_ELEMENTS( or );	/* Number of elements */

	int x, y, z, i;

	/* Get input ready.
	 */
	if( vips_region_prepare( ir, r ) )
		return( -1 );

	/* Process!
	 */
	if( st->nb == 1 )
		/* One band lut.
		 */
		outer_switch( loop1, loop1c, loop1g, loop1cg ) 
	else 
		/* Many band lut.
		 */
		if( ir->im->Bands == 1 )
			/* ... but 1 band input.
			 */
			outer_switch( loop1m, loop1cm, loop1gm, loop1cgm ) 
		else
			outer_switch( loop, loopc, loopg, loopcg )

	return( 0 );
}

/* Destroy a sequence value.
 */
static int
vips_maplut_stop( void *vseq, void *a, void *b )
{
	VipsMaplutSequence *seq = (VipsMaplutSequence *) vseq;
	VipsMaplut *maplut = (VipsMaplut *) b;

	/* Add to global stats.
	 */
	maplut->overflow += seq->overflow;

	VIPS_UNREF( seq->ir );

	return( 0 );
}

/* Save a bit of typing.
 */
#define UC VIPS_FORMAT_UCHAR
#define US VIPS_FORMAT_USHORT
#define UI VIPS_FORMAT_UINT

/* Type mapping: go to uchar / ushort / uint to make an index. 
 */
static int bandfmt_maplut[10] = {
/* UC   C  US   S  UI   I   F   X  D   DX */
   UC, UC, US, US, UI, UI, UI, UI, UI, UI
};

static int
vips_maplut_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMaplut *maplut = (VipsMaplut *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 1 );

	VipsImage *in;
	VipsImage *lut;
	int i, x;
	VipsPel *q;

	g_object_set( maplut, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_maplut_parent_class )->build( object ) )
		return( -1 );

	in = maplut->in;
	lut = maplut->lut;

	if( vips_check_hist( class->nickname, lut ) ||
		vips_check_uncoded( class->nickname, lut ) ||
		vips_image_wio_input( lut ) )
		return( -1 );

	/* Cast @in to u8/u16/u32 to make the index image.
	 */
	if( vips_cast( in, &t[0], bandfmt_maplut[in->BandFmt], NULL ) )
		return( -1 );
	in = t[0];

	if( vips_check_uncoded( class->nickname, in ) ||
		vips_check_bands_1orn( class->nickname, in, lut ) ||
		vips_image_pio_input( in ) )
		return( -1 );

	if( vips_image_copy_fieldsv( maplut->out, in, lut, NULL ) )
		return( -1 );
	vips_demand_hint( maplut->out, VIPS_DEMAND_STYLE_THINSTRIP, 
		in, lut, NULL );
	maplut->out->BandFmt = lut->BandFmt;

	/* Output has same number of bands as LUT, unless LUT has 1 band, in
	 * which case output has same number of bands as input.
	 */
	if( lut->Bands != 1 )
		maplut->out->Bands = lut->Bands;

	g_signal_connect( in, "preeval", 
		G_CALLBACK( vips_maplut_preeval ), maplut );
	g_signal_connect( in, "posteval", 
		G_CALLBACK( vips_maplut_posteval ), maplut );

	/* Make luts. We unpack the LUT image into a 2D C array to speed
	 * processing.
	 */
	maplut->fmt = lut->BandFmt;
	maplut->es = VIPS_IMAGE_SIZEOF_ELEMENT( lut );
	maplut->nb = lut->Bands;
	maplut->sz = lut->Xsize * lut->Ysize;
	maplut->clp = maplut->sz - 1;

	/* Attach tables.
	 */
	if( !(maplut->table = VIPS_ARRAY( maplut, lut->Bands, VipsPel * )) ) 
                return( -1 );
	for( i = 0; i < lut->Bands; i++ )
		if( !(maplut->table[i] = VIPS_ARRAY( maplut, 
			maplut->sz * maplut->es, VipsPel )) )
			return( -1 );

	/* Scan LUT and fill table.
	 */
	q = (VipsPel *) lut->data;
	for( x = 0; x < maplut->sz; x++ )
		for( i = 0; i < maplut->nb; i++ ) {
			memcpy( maplut->table[i] + x * maplut->es, q, 
				maplut->es );
			q += maplut->es;
		}

	if( vips_image_generate( maplut->out,
		vips_maplut_start, vips_maplut_gen, vips_maplut_stop, 
		in, maplut ) )
		return( -1 );

	return( 0 );
}

static void
vips_maplut_class_init( VipsMaplutClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "maplut";
	vobject_class->description = _( "map an image though a lut" );
	vobject_class->build = vips_maplut_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL;

	VIPS_ARG_IMAGE( class, "in", 0, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT, 
		G_STRUCT_OFFSET( VipsHistogram, in ) );

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsHistogram, out ) );

	VIPS_ARG_IMAGE( class, "lut", 2, 
		_( "LUT" ), 
		_( "Look-up table image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaplut, lut ) );

}

static void
vips_maplut_init( VipsMaplut *maplut )
{
}

/**
 * vips_maplut:
 * @in: input image
 * @out: output image
 * @lut: look-up table
 * @...: %NULL-terminated list of optional named arguments
 *
 * Map an image through another image acting as a LUT (Look Up Table). 
 * The lut may have any type and the output image will be that type.
 * 
 * The input image will be cast to one of the unsigned integer types, that is,
 * VIPS_FORMAT_UCHAR, VIPS_FORMAT_USHORT or VIPS_FORMAT_UINT.
 * 
 * If @lut is too small for the input type (for example, if @in is
 * VIPS_FORMAT_UCHAR but @lut only has 100 elements), the lut is padded out
 * by copying the last element. Overflows are reported at the end of 
 * computation.
 * If @lut is too large, extra values are ignored. 
 * 
 * If @lut has one band, then all bands of @in pass through it. If @lut
 * has same number of bands as @in, then each band is mapped
 * separately. If @in has one band, then @lut may have many bands and
 * the output will have the same number of bands as @lut.
 *
 * See also: im_histgr(), vips_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_maplut( VipsImage *in, VipsImage **out, VipsImage *lut, ... )
{
	va_list ap;
	int result;

	va_start( ap, lut );
	result = vips_call_split( "maplut", ap, in, out, lut );
	va_end( ap );

	return( result );
}

