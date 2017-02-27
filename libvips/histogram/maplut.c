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
 * 2/10/13
 * 	- add --band arg, replacing im_tone_map()
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

typedef struct _VipsMaplut {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;
	VipsImage *lut;
	int band; 

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
	if( maplut->overflow )
		g_warning( _( "%d overflows detected" ), maplut->overflow );
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
	int b = maplut->nb; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
			OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
			OUT *tlut = (OUT *) maplut->table[z]; \
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
			OUT *tlut = (OUT *) maplut->table[z]; \
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
	int b = maplut->nb; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
			OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
			OUT *tlut = (OUT *) maplut->table[z]; \
			\
			for( x = z; x < ne; x += b ) { \
				int index = p[x]; \
				\
				if( index > maplut->clp ) { \
					index = maplut->clp; \
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
			OUT *tlut = (OUT *) maplut->table[z]; \
			\
			for( x = 0; x < ne; x += b ) { \
				int index = p[x]; \
				\
				if( index > maplut->clp ) { \
					index = maplut->clp; \
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
	OUT *tlut = (OUT *) maplut->table[0]; \
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
	OUT *tlut = (OUT *) maplut->table[0]; \
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
	OUT *tlut = (OUT *) maplut->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) { \
			int index = p[x]; \
			\
			if( index > maplut->clp ) { \
				index = maplut->clp; \
				seq->overflow++; \
			} \
			\
			q[x] = tlut[index]; \
		} \
	} \
}

#define loop1cg( IN, OUT ) { \
	OUT *tlut = (OUT *) maplut->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) { \
			int index = p[x]; \
			\
			if( index > maplut->clp ) { \
				index = maplut->clp; \
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
	OUT **tlut = (OUT **) maplut->table; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( i = 0, x = 0; x < np; x++ ) { \
			int n = p[x]; \
			\
			for( z = 0; z < maplut->nb; z++, i++ ) \
				q[i] = tlut[z][n]; \
		} \
	} \
}

/* Map 1-band image through many-band complex lut.
 */
#define loop1cm( OUT ) { \
	OUT **tlut = (OUT **) maplut->table; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		VipsPel *p = VIPS_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < np; x++ ) { \
			int n = p[x] * 2; \
			\
			for( z = 0; z < maplut->nb; z++ ) { \
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
	OUT **tlut = (OUT **) maplut->table; \
	\
	for( y = to; y < bo; y++ ) { \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		\
		for( i = 0, x = 0; x < np; x++ ) { \
			int n = p[x]; \
			\
			if( n > maplut->clp ) { \
				n = maplut->clp; \
				seq->overflow++; \
			} \
			\
			for( z = 0; z < maplut->nb; z++, i++ ) \
				q[i] = tlut[z][n]; \
		} \
	} \
}

/* Map 1-band uint or ushort image through a many-band complex LUT.
 */
#define loop1cgm( IN, OUT ) { \
	OUT **tlut = (OUT **) maplut->table; \
	\
	for( y = to; y < bo; y++ ) { \
		IN *p = (IN *) VIPS_REGION_ADDR( ir, le, y ); \
		OUT *q = (OUT *) VIPS_REGION_ADDR( or, le, y ); \
		\
		for( x = 0; x < np; x++ ) { \
			int n = p[x]; \
			\
			if( n > maplut->clp ) { \
				n = maplut->clp; \
				seq->overflow++; \
			} \
			\
			for( z = 0; z < maplut->nb; z++ ) { \
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
		g_assert_not_reached(); \
	}

/* Switch for LUT types. One function for non-complex images, a
 * variant for complex ones. Another pair as well, in case the input is not
 * uchar.
 */
#define outer_switch( UCHAR_F, UCHAR_FC, GEN_F, GEN_FC ) \
	switch( maplut->fmt ) { \
	case VIPS_FORMAT_UCHAR: \
		inner_switch( UCHAR_F, GEN_F, unsigned char ); break; \
	case VIPS_FORMAT_CHAR:\
		inner_switch( UCHAR_F, GEN_F, char ); break; \
	case VIPS_FORMAT_USHORT: \
		inner_switch( UCHAR_F, GEN_F, unsigned short ); break; \
	case VIPS_FORMAT_SHORT: \
		inner_switch( UCHAR_F, GEN_F, short ); break; \
	case VIPS_FORMAT_UINT: \
		inner_switch( UCHAR_F, GEN_F, unsigned int ); break; \
	case VIPS_FORMAT_INT: \
		inner_switch( UCHAR_F, GEN_F, int ); break; \
	case VIPS_FORMAT_FLOAT: \
		inner_switch( UCHAR_F, GEN_F, float ); break; \
	case VIPS_FORMAT_DOUBLE: \
		inner_switch( UCHAR_F, GEN_F, double ); break; \
	case VIPS_FORMAT_COMPLEX: \
		inner_switch( UCHAR_FC, GEN_FC, float ); break; \
	case VIPS_FORMAT_DPCOMPLEX: \
		inner_switch( UCHAR_FC, GEN_FC, double ); break; \
	default: \
		g_assert_not_reached(); \
	}

/* Do a map.
 */
static int 
vips_maplut_gen( VipsRegion *or, void *vseq, void *a, void *b, 
	gboolean *stop )
{
	VipsMaplutSequence *seq = (VipsMaplutSequence *) vseq;
	VipsImage *in = (VipsImage *) a;
	VipsMaplut *maplut = (VipsMaplut *) b;
	VipsRegion *ir = seq->ir;
	VipsRect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = VIPS_RECT_BOTTOM( r );
	int np = r->width;			/* Pels across region */
	int ne = VIPS_REGION_N_ELEMENTS( or );	/* Number of elements */

	int x, y, z, i;

	if( vips_region_prepare( ir, r ) )
		return( -1 );

	if( maplut->nb == 1 )
		/* One band lut.
		 */
		outer_switch( loop1, loop1c, loop1g, loop1cg ) 
	else 
		/* Many band lut.
		 */
		if( in->Bands == 1 )
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

/* Repack lut into a set of band arrays. If we're just passing one band of the
 * image through the lut, put the identity function in the other bands. 
 */ 
#define PACK_TABLE( TYPE ) { \
	TYPE *data = (TYPE *) lut->data; \
	int x, b; \
	\
	for( x = 0; x < maplut->sz; x++ ) \
		for( b = 0; b < maplut->nb; b++ ) { \
			TYPE *q = (TYPE *) maplut->table[b];  \
			\
			if( maplut->band >= 0 && \
				lut->Bands == 1 ) { \
				if( b == maplut->band ) \
					q[x] = data[x]; \
				else \
					q[x] = x; \
			} \
			else \
				q[x] = data[x * lut->Bands + b]; \
		} \
}

#define PACK_TABLEC( TYPE ) { \
	TYPE *data = (TYPE *) lut->data; \
	int x, b; \
	\
	for( x = 0; x < maplut->sz; x++ ) \
		for( b = 0; b < maplut->nb; b++ ) { \
			TYPE *q = (TYPE *) maplut->table[b];  \
			\
			if( maplut->band >= 0 && \
				lut->Bands == 1 ) { \
				if( b == maplut->band ) { \
					q[2 * x] = data[2 * x]; \
					q[2 * x + 1] = data[2 * x + 1]; \
				} \
				else { \
					q[2 * x] = x; \
					q[2 * x + 1] = 0; \
				} \
			} \
			else { \
				q[2 * x] = data[2 * (x * lut->Bands + b)]; \
				q[2 * x + 1] = \
					data[2 * (x * lut->Bands + b) + 1]; \
			} \
		} \
}

static int
vips_maplut_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMaplut *maplut = (VipsMaplut *) object;
	VipsImage **t = (VipsImage **) vips_object_local_array( object, 2 );

	VipsImage *in;
	VipsImage *lut;
	int i;

	g_object_set( object, "out", vips_image_new(), NULL ); 

	if( VIPS_OBJECT_CLASS( vips_maplut_parent_class )->build( object ) )
		return( -1 );

	in = maplut->in;
	lut = maplut->lut;

	if( vips_check_hist( class->nickname, lut ) ||
		vips_check_uncoded( class->nickname, lut ) )
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

	if( vips_image_pipelinev( maplut->out, 
		VIPS_DEMAND_STYLE_THINSTRIP, in, lut, NULL ) )
		return( -1 );
	maplut->out->BandFmt = lut->BandFmt;

	/* Output has same number of bands as LUT, unless LUT has 1 band, in
	 * which case output has same number of bands as input.
	 */
	if( lut->Bands != 1 )
		maplut->out->Bands = lut->Bands;

	/* The Type comes from the image with many bands. A B_W index image,
	 * for example, needs to become an RGB image when it goes through a
	 * three-band LUT.
	 */
	if( lut->Bands != 1 )
		maplut->out->Type = lut->Type;

	g_signal_connect( in, "preeval", 
		G_CALLBACK( vips_maplut_preeval ), maplut );
	g_signal_connect( in, "posteval", 
		G_CALLBACK( vips_maplut_posteval ), maplut );

	/* Make luts. We unpack the LUT image into a 2D C array to speed
	 * processing.
	 */
	if( !(t[1] = vips_image_copy_memory( lut )) )
		return( -1 );
	lut = t[1];
	maplut->fmt = lut->BandFmt;
	maplut->es = VIPS_IMAGE_SIZEOF_ELEMENT( lut );
	maplut->sz = lut->Xsize * lut->Ysize;
	maplut->clp = maplut->sz - 1;

	/* If @bands is >= 0, we need to expand the lut to the number of bands
	 * in the input image. 
	 */
	if( maplut->band >= 0 && 
		lut->Bands == 1 )
		maplut->nb = in->Bands;
	else
		maplut->nb = lut->Bands;

	/* Attach tables.
	 */
	if( !(maplut->table = VIPS_ARRAY( maplut, maplut->nb, VipsPel * )) ) 
                return( -1 );
	for( i = 0; i < maplut->nb; i++ )
		if( !(maplut->table[i] = VIPS_ARRAY( maplut, 
			maplut->sz * maplut->es, VipsPel )) )
			return( -1 );

	/* Scan LUT and fill table.
	 */
	switch( lut->BandFmt ) {
	case VIPS_FORMAT_UCHAR: 
		PACK_TABLE( unsigned char ); break; 
	case VIPS_FORMAT_CHAR:
		PACK_TABLE( char ); break; 
	case VIPS_FORMAT_USHORT: 
		PACK_TABLE( unsigned short ); break; 
	case VIPS_FORMAT_SHORT: 
		PACK_TABLE( short ); break; 
	case VIPS_FORMAT_UINT: 
		PACK_TABLE( unsigned int ); break; 
	case VIPS_FORMAT_INT: 
		PACK_TABLE( int ); break; 
	case VIPS_FORMAT_FLOAT: 
		PACK_TABLE( float ); break; 
	case VIPS_FORMAT_DOUBLE: 
		PACK_TABLE( double ); break; 
	case VIPS_FORMAT_COMPLEX: 
		PACK_TABLEC( float ); break; 
	case VIPS_FORMAT_DPCOMPLEX: 
		PACK_TABLEC( double ); break; 
	default: 
		g_assert_not_reached(); 
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
	VipsObjectClass *object_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	object_class->nickname = "maplut";
	object_class->description = _( "map an image though a lut" );
	object_class->build = vips_maplut_build;

	operation_class->flags = VIPS_OPERATION_SEQUENTIAL_UNBUFFERED;

	VIPS_ARG_IMAGE( class, "in", 1, 
		_( "Input" ), 
		_( "Input image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaplut, in ) );

	VIPS_ARG_IMAGE( class, "out", 2, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMaplut, out ) );

	VIPS_ARG_IMAGE( class, "lut", 3, 
		_( "LUT" ), 
		_( "Look-up table image" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMaplut, lut ) );

	VIPS_ARG_INT( class, "band", 4, 
		_( "band" ), 
		_( "apply one-band lut to this band of in" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsMaplut, band ),
		-1, 10000, -1 ); 

}

static void
vips_maplut_init( VipsMaplut *maplut )
{
	maplut->band = -1;
}

/**
 * vips_maplut:
 * @in: input image
 * @out: output image
 * @lut: look-up table
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * * @band: apply one-band @lut to this band of @in
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
 * If @lut has one band and @band is -1 (the default), then all bands of @in 
 * pass through @lut. If @band is >= 0, then just that band of @in passes 
 * through @lut and other bands are just copied. 
 *
 * If @lut
 * has same number of bands as @in, then each band is mapped
 * separately. If @in has one band, then @lut may have many bands and
 * the output will have the same number of bands as @lut.
 *
 * See also: vips_hist_find(), vips_identity().
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

