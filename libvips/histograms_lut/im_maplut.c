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

/* Struct we carry for LUT operations.
 */
typedef struct {
	int fmt;		/* LUT image BandFmt */
	int nb;			/* Number of bands in lut */
	int es;			/* IM_IMAGE_SIZEOF_ELEMENT() for lut image */
	int sz;			/* Number of elements in minor dimension */
	int clp;		/* Value we clip against */
	VipsPel **table;		/* Lut converted to 2d array */
	int overflow;		/* Number of overflows for non-uchar lut */
} LutInfo;

static int
lut_start( LutInfo *st )
{
	st->overflow = 0;

	return( 0 );
}

/* Print overflows, if any.
 */
static int
lut_end( LutInfo *st )
{
	if( st->overflow ) 
		im_warn( "im_maplut", _( "%d overflows detected" ), 
			st->overflow );

	return( 0 );
}

/* Build a lut table.
 */
static LutInfo *
build_luts( IMAGE *out, IMAGE *lut )
{
	LutInfo *st;
	int i, x;
	VipsPel *q;

	if( !(st = IM_NEW( out, LutInfo )) )
                return( NULL );

	/* Make luts. We unpack the LUT image into a C 2D array to speed
	 * processing.
	 */
	st->fmt = lut->BandFmt;
	st->es = IM_IMAGE_SIZEOF_ELEMENT( lut );
	st->nb = lut->Bands;
	st->sz = lut->Xsize * lut->Ysize;
	st->clp = st->sz - 1;
	st->overflow = 0;
	st->table = NULL;
	if( im_add_evalstart_callback( out, 
		(im_callback_fn) lut_start, st, NULL ) || 
		im_add_evalend_callback( out, 
			(im_callback_fn) lut_end, st, NULL ) ) 
		return( NULL );

	/* Attach tables.
	 */
	if( !(st->table = IM_ARRAY( out, lut->Bands, VipsPel * )) ) 
                return( NULL );
	for( i = 0; i < lut->Bands; i++ )
		if( !(st->table[i] = IM_ARRAY( out, st->sz * st->es, VipsPel )) )
			return( NULL );

	/* Scan LUT and fill table.
	 */
	q = (VipsPel *) lut->data;
	for( x = 0; x < st->sz; x++ )
		for( i = 0; i < st->nb; i++ ) {
			memcpy( st->table[i] + x * st->es, q, st->es );
			q += st->es;
		}
	
	return( st );
}

/* Our sequence value: the region this sequence is using, and local stats.
 */
typedef struct {
	REGION *ir;		/* Input region */
	int overflow;		/* Number of overflows */
} Seq;

/* Destroy a sequence value.
 */
static int
maplut_stop( void *vseq, void *a, void *b )
{
	Seq *seq = (Seq *) vseq;
	LutInfo *st = (LutInfo *) b;

	/* Add to global stats.
	 */
	st->overflow += seq->overflow;
	
	IM_FREEF( im_region_free, seq->ir );

	return( 0 );
}

/* Our start function.
 */
static void *
maplut_start( IMAGE *out, void *a, void *b )
{
	IMAGE *in = (IMAGE *) a;
	Seq *seq;

	if( !(seq = IM_NEW( out, Seq )) )
		 return( NULL );

	/* Init!
	 */
	seq->ir = NULL;
	seq->overflow = 0;

	if( !(seq->ir = im_region_create( in )) ) 
		return( NULL );

	return( seq );
}

/* Map through n non-complex luts.
 */
#define loop(OUT) { \
	int b = st->nb; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			VipsPel *p = IM_REGION_ADDR( ir, le, y ); \
			OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
			OUT *tlut = (OUT *) st->table[z]; \
			\
			for( x = z; x < ne; x += b ) \
				q[x] = tlut[p[x]]; \
		} \
	} \
}

/* Map through n complex luts.
 */
#define loopc(OUT) { \
	int b = in->Bands; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			VipsPel *p = IM_REGION_ADDR( ir, le, y ) + z; \
			OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ) + z * 2; \
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

#define loopg(IN,OUT) { \
	int b = st->nb; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			IN *p = (IN *) IM_REGION_ADDR( ir, le, y ); \
			OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
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

#define loopcg(IN,OUT) { \
	int b = in->Bands; \
	\
	for( y = to; y < bo; y++ ) { \
		for( z = 0; z < b; z++ ) { \
			IN *p = (IN *) IM_REGION_ADDR( ir, le, y ) + z; \
			OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ) + z * 2; \
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
#define loop1(OUT) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
		VipsPel *p = IM_REGION_ADDR( ir, le, y ); \
		\
		for( x = 0; x < ne; x++ ) \
			q[x] = tlut[p[x]]; \
	} \
}

/* Map image through one complex lut.
 */
#define loop1c(OUT) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
		VipsPel *p = IM_REGION_ADDR( ir, le, y ); \
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
#define loop1g(IN,OUT) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
		IN *p = (IN *) IM_REGION_ADDR( ir, le, y ); \
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

#define loop1cg(IN,OUT) { \
	OUT *tlut = (OUT *) st->table[0]; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
		IN *p = (IN *) IM_REGION_ADDR( ir, le, y ); \
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
#define loop1m(OUT) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
		VipsPel *p = IM_REGION_ADDR( ir, le, y ); \
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
#define loop1cm(OUT) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
		VipsPel *p = IM_REGION_ADDR( ir, le, y ); \
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
#define loop1gm(IN,OUT) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		IN *p = (IN *) IM_REGION_ADDR( ir, le, y ); \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
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
#define loop1cgm(IN,OUT) { \
	OUT **tlut = (OUT **) st->table; \
	\
	for( y = to; y < bo; y++ ) { \
		IN *p = (IN *) IM_REGION_ADDR( ir, le, y ); \
		OUT *q = (OUT *) IM_REGION_ADDR( or, le, y ); \
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
	case IM_BANDFMT_UCHAR:		UCHAR( OUT ); break; \
	case IM_BANDFMT_USHORT:		GEN( unsigned short, OUT ); break; \
	case IM_BANDFMT_UINT:		GEN( unsigned int, OUT ); break; \
	default: \
		g_assert( 0 ); \
	}

/* Switch for LUT types. One function for non-complex images, a
 * variant for complex ones. Another pair as well, in case the input is not
 * uchar.
 */
#define outer_switch( UCHAR_F, UCHAR_FC, GEN_F, GEN_FC ) \
	switch( st->fmt ) { \
	case IM_BANDFMT_UCHAR:		inner_switch( UCHAR_F, GEN_F, \
					unsigned char ); break; \
	case IM_BANDFMT_CHAR:		inner_switch( UCHAR_F, GEN_F, \
					char ); break; \
	case IM_BANDFMT_USHORT:		inner_switch( UCHAR_F, GEN_F, \
					unsigned short ); break; \
	case IM_BANDFMT_SHORT:		inner_switch( UCHAR_F, GEN_F, \
					short ); break; \
	case IM_BANDFMT_UINT:		inner_switch( UCHAR_F, GEN_F, \
					unsigned int ); break; \
	case IM_BANDFMT_INT:		inner_switch( UCHAR_F, GEN_F, \
					int ); break; \
	case IM_BANDFMT_FLOAT:		inner_switch( UCHAR_F, GEN_F, \
					float ); break; \
	case IM_BANDFMT_DOUBLE:		inner_switch( UCHAR_F, GEN_F, \
					double ); break; \
	case IM_BANDFMT_COMPLEX:	inner_switch( UCHAR_FC, GEN_FC, \
					float ); break; \
	case IM_BANDFMT_DPCOMPLEX:	inner_switch( UCHAR_FC, GEN_FC, \
					double ); break; \
	default: \
		g_assert( 0 ); \
	}

/* Do a map.
 */
static int 
maplut_gen( REGION *or, void *vseq, void *a, void *b )
{
	Seq *seq = (Seq *) vseq;
	IMAGE *in = (IMAGE *) a;
	LutInfo *st = (LutInfo *) b;
	REGION *ir = seq->ir;
	Rect *r = &or->valid;
	int le = r->left;
	int to = r->top;
	int bo = IM_RECT_BOTTOM(r);
	int np = r->width;			/* Pels across region */
	int ne = IM_REGION_N_ELEMENTS( or );	/* Number of elements */
	int x, y, z, i;

	/* Get input ready.
	 */
	if( im_prepare( ir, r ) )
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

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define US IM_BANDFMT_USHORT
#define UI IM_BANDFMT_UINT

/* Type mapping: go to uchar or ushort.
 */
static int bandfmt_maplut[10] = {
/* UC   C  US   S  UI   I   F   X  D   DX */
   UC, UC, US, US, UI, UI, UI, UI, UI, UI
};

/**
 * im_maplut:
 * @in: input image
 * @out: output image
 * @lut: look-up table
 *
 * Map an image through another image acting as a LUT (Look Up Table). 
 * The lut may have any type, and the output image will be that type.
 * 
 * The input image will be cast to one of the unsigned integer types, that is,
 * IM_BANDFMT_UCHAR, IM_BANDFMT_USHORT or IM_BANDFMT_UINT.
 * 
 * If @lut is too small for the input type (for example, if @in is
 * IM_BANDFMT_UCHAR but @lut only has 100 elements), the lut is padded out
 * by copying the last element. Overflows are reported at the end of 
 * computation.
 * If @lut is too large, extra values are ignored. 
 * 
 * If @lut has one band, then all bands of @in pass through it. If @lut
 * has same number of bands as @in, then each band is mapped
 * separately. If @in has one band, then @lut may have many bands and
 * the output will have the same number of bands as @lut.
 *
 * See also: im_histgr(), im_identity().
 *
 * Returns: 0 on success, -1 on error
 */
int 
im_maplut( IMAGE *in, IMAGE *out, IMAGE *lut )
{
	IMAGE *t;
	LutInfo *st;

	/* Check input output. Old-style IO from lut, for simplicity.
	 */
	if( im_check_hist( "im_maplut", lut ) ||
		im_check_uncoded( "im_maplut", lut ) ||
		im_check_uncoded( "im_maplut", in ) ||
		im_check_bands_1orn( "im_maplut", in, lut ) ||
		im_piocheck( in, out ) || 
		im_incheck( lut ) )
		return( -1 );

	/* Cast in to u8/u16/u32.
	 */
	if( !(t = im_open_local( out, "im_maplut", "p" )) ||
		im_clip2fmt( in, t, bandfmt_maplut[in->BandFmt] ) )
		return( -1 );

	/* Prepare the output header.
	 */
        if( im_cp_descv( out, t, lut, NULL ) )
                return( -1 );

	/* Force output to be the same type as lut.
	 */
	out->BandFmt = lut->BandFmt;

	/* Output has same number of bands as LUT, unless LUT has 1 band, in
	 * which case output has same number of bands as input.
	 */
	if( lut->Bands != 1 )
		out->Bands = lut->Bands;

	/* Make tables.
	 */
	if( !(st = build_luts( out, lut )) )
		return( -1 );

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, t, NULL ) )
		return( -1 );

	/* Process!
	 */
        if( im_generate( out, maplut_start, maplut_gen, maplut_stop, t, st ) )
                return( -1 );

        return( 0 );
}
