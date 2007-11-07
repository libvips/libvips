/* @(#) Copy an image. 
 * @(#)
 * @(#) int 
 * @(#) im_copy( in, out )
 * @(#) IMAGE *in, *out;
 * @(#)
 * @(#) Copy and set informational header fields
 * @(#)
 * @(#) int im_copy_set( in, out, type, xres, yres, xoff, yoff )
 * @(#) IMAGE *in, *out;
 * @(#) int type;
 * @(#) float xres, yres;
 * @(#) int xoff, yoff;
 * @(#)
 * @(#) copy, swapping byte order
 * @(#)
 * @(#) int
 * @(#) im_copy_swap( IMAGE *in, IMAGE *out )
 * @(#)
 * @(#) Returns 0 on success and -1 on error
 * @(#)
 *
 * Copyright: 1990, N. Dessipris, based on im_powtra()
 * Author: Nicos Dessipris
 * Written on: 02/05/1990
 * Modified on: 
 * 23/4/93 J.Cupitt
 *	- adapted to work with partial images
 * 30/6/93 JC
 *	- adapted for partial v2
 *	- and ANSI C
 * 7/7/93 JC
 *	- now does IM_CODING_LABQ too
 * 22/2/95 JC
 *	- new use of im_region_region()
 * 25/6/02 JC
 *	- added im_copy_set()
 *	- hint is IM_ANY
 * 5/9/02 JC
 *	- added xoff/yoff to copy_set
 * 14/4/04 JC
 *	- im_copy() now zeros Xoffset/Yoffset (since origin is the same as
 *	  input)
 * 26/5/04 JC
 *	- added im_copy_swap()
 * 1/6/05
 *	- added im_copy_morph()
 * 13/6/05
 *	- oop, im_copy_set() was messed up
 * 29/9/06
 * 	- added im_copy_set_meta(), handy wrapper for nip2 to set meta fields
 * 2/11/06
 * 	- moved im__convert_saveable() here so it's always defined (was part
 * 	  of JPEG write code)
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
#include <math.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Copy a small area.
 */
static int
copy_gen( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;
	Rect *r = &or->valid;

	/* Ask for input we need.
	 */
	if( im_prepare( ir, r ) )
		return( -1 );

	/* Attach output region to that.
	 */
	if( im_region_region( or, ir, r, r->left, r->top ) )
		return( -1 );

	return( 0 );
}

/* Copy image, changing header fields.
 */
static int 
im_copy_set_all( IMAGE *in, IMAGE *out, 
	int Type, float Xres, float Yres, int Xoffset, int Yoffset,
	int Bands, int BandFmt, int Coding )
{	
	/* Check args.
	 */
        if( im_piocheck( in, out ) )
		return( -1 );
	if( in->Coding != IM_CODING_NONE && in->Coding != IM_CODING_LABQ ) {
		im_error( "im_copy", _( "in must be uncoded" ) );
		return( -1 );
	}
	if( Coding != IM_CODING_NONE && Coding != IM_CODING_LABQ ) {
		im_error( "im_copy", _( "Coding must be NONE or LABQ" ) );
		return( -1 );
	}
	if( BandFmt < 0 || BandFmt > IM_BANDFMT_DPCOMPLEX ) {
		im_error( "im_copy", _( "BandFmt must be in range [0,%d]" ),
			IM_BANDFMT_DPCOMPLEX );
		return( -1 );
	}

	/* Prepare output header.
	 */
	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = Type;
	out->Xres = Xres;
	out->Yres = Yres;
	out->Xoffset = Xoffset;
	out->Yoffset = Yoffset;
	out->Bands = Bands;
	out->BandFmt = BandFmt;
	out->Coding = Coding;
	out->Bbits = im_bits_of_fmt( BandFmt );

	/* Sanity check: we (may) have changed bytes-per-pixel since we've
	 * changed Bands and BandFmt ... bad!
	 */
	if( IM_IMAGE_SIZEOF_PEL( in ) != IM_IMAGE_SIZEOF_PEL( out ) ) {
		im_error( "im_copy", _( "sizeof( pixel ) has changed" ) );
		return( -1 );
	}

	/* Set demand hints.
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) )
		return( -1 );

	/* Generate!
	 */
	if( im_generate( out, im_start_one, copy_gen, im_stop_one, in, NULL ) )
		return( -1 );

	return( 0 );
}

/* Copy image, changing informational header fields.
 */
int 
im_copy_set( IMAGE *in, IMAGE *out, 
	int Type, float Xres, float Yres, int Xoffset, int Yoffset )
{
	return( im_copy_set_all( in, out, 
		Type, Xres, Yres, 0, 0,
		in->Bands, in->BandFmt, in->Coding ) );
}

/* Copy image, changing nothing.
 */
int 
im_copy( IMAGE *in, IMAGE *out )
{
	return( im_copy_set( in, out, 
		in->Type, in->Xres, in->Yres, 0, 0 ) );
}

/* Copy image, changing fields which affect pixel layout.
 */
int 
im_copy_morph( IMAGE *in, IMAGE *out, 
	int Bands, int BandFmt, int Coding )
{
	return( im_copy_set_all( in, out, 
		in->Type, in->Xres, in->Yres, 0, 0,
		Bands, BandFmt, Coding ) );
}

int
im_copy_set_meta( IMAGE *in, IMAGE *out, const char *field, GValue *value )
{
	if( im_copy( in, out ) ||
		im_meta_set( out, field, value ) )
		return( 1 );

	return( 0 );
}

/* Swap pairs of bytes.
 */
static void
im_copy_swap2_gen( PEL *in, PEL *out, int width, IMAGE *im )
{       
        int x;
        int sz = IM_IMAGE_SIZEOF_PEL( im ) * width;     /* Bytes in buffer */

        for( x = 0; x < sz; x += 2 ) {
                out[x] = in[x + 1];
                out[x + 1] = in[x];
        }
}

/* Swap 4- of bytes.
 */
static void
im_copy_swap4_gen( PEL *in, PEL *out, int width, IMAGE *im )
{
        int x;
        int sz = IM_IMAGE_SIZEOF_PEL( im ) * width;     /* Bytes in buffer */

        for( x = 0; x < sz; x += 4 ) {
                out[x] = in[x + 3];
                out[x + 1] = in[x + 2];
                out[x + 2] = in[x + 1];
                out[x + 3] = in[x];
        }
}

/* Swap 8- of bytes.
 */
static void
im_copy_swap8_gen( PEL *in, PEL *out, int width, IMAGE *im )
{
        int x;
        int sz = IM_IMAGE_SIZEOF_PEL( im ) * width;     /* Bytes in buffer */

        for( x = 0; x < sz; x += 8 ) {
                out[x] = in[x + 7];
                out[x + 1] = in[x + 6];
                out[x + 2] = in[x + 5];
                out[x + 3] = in[x + 4];
                out[x + 4] = in[x + 3];
                out[x + 5] = in[x + 2];
                out[x + 6] = in[x + 1];
                out[x + 7] = in[x];
        }
}

/* Copy, swapping byte order between little and big endian.
 */
int
im_copy_swap( IMAGE *in, IMAGE *out )
{
        if( im_piocheck( in, out ) )
                return( -1 );
        if( in->Coding != IM_CODING_NONE ) {
                im_error( "im_copy_swap", _( "in must be uncoded" ) );
                return( -1 );
        }
        if( im_cp_desc( out, in ) )
                return( -1 );

	switch( in->BandFmt ) {
        case IM_BANDFMT_CHAR:
        case IM_BANDFMT_UCHAR:
		if( im_copy( in, out ) ) 
			return( -1 );
		break;

        case IM_BANDFMT_SHORT:
        case IM_BANDFMT_USHORT:
		if( im_wrapone( in, out, 
			(im_wrapone_fn) im_copy_swap2_gen, in, NULL ) )
			return( -1 );
		break;

	case IM_BANDFMT_INT:
	case IM_BANDFMT_UINT:
	case IM_BANDFMT_FLOAT:
	case IM_BANDFMT_COMPLEX:
		if( im_wrapone( in, out, 
			(im_wrapone_fn) im_copy_swap4_gen, in, NULL ) )
			return( -1 );
		break;

        case IM_BANDFMT_DOUBLE:
        case IM_BANDFMT_DPCOMPLEX:
		if( im_wrapone( in, out, 
			(im_wrapone_fn) im_copy_swap8_gen, in, NULL ) )
			return( -1 );
		break;

	default:
		im_error( "im_copy_swap", _( "unsupported image type" ) );
		return( -1 );
	}

	return( 0 );
}

int
im_copy_from( IMAGE *in, IMAGE *out, im_arch_type architecture )
{
	switch( architecture ) {
	case IM_ARCH_NATIVE:
		return( im_copy( in, out ) );

	case IM_ARCH_BYTE_SWAPPED:
		return( im_copy_swap( in, out ) );

	case IM_ARCH_LSB_FIRST:
		return( im_amiMSBfirst() ? 
			im_copy_swap( in, out ) : im_copy( in, out ) );

	case IM_ARCH_MSB_FIRST:
		return( im_amiMSBfirst() ? 
			im_copy( in, out ) : im_copy_swap( in, out ) );

	default:
		im_error( "im_copy_from", 
			_( "bad architecture: %d" ), architecture );
		return( -1 );
	}
}

/* Convert to 1 or 3 band uchar sRGB (or 2/4 band, if allow_alpha is set). 
 * Need to im_close() the return IMAGE.
 */
IMAGE *
im__convert_saveable( IMAGE *in, gboolean allow_alpha )
{
	IMAGE *out;

	if( !(out = im_open( "convert-for-save", "p" )) )
		return( NULL );

	/* If this is a IM_CODING_LABQ, we can go straight to RGB.
	 */
	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t = im_open_local( out, "conv:1", "p" );
		static void *table = NULL;

		/* Make sure fast LabQ2disp tables are built. 7 is sRGB.
		 */
		if( !table ) 
			table = im_LabQ2disp_build_table( NULL, 
				im_col_displays( 7 ) );

		if( !t || im_LabQ2disp_table( in, t, table ) ) {
			im_close( out );
			return( NULL );
		}

		in = t;
	}

	/* Get the bands right. If we have >3, drop down to 3. If we have 2,
	 * drop down to 1. If allow_alpha is on, we can also have 2/4 bands.
	 */
	if( in->Coding == IM_CODING_NONE ) {
		if( in->Bands == 2  && !allow_alpha ) {
			IMAGE *t = im_open_local( out, "conv:1", "p" );

			if( !t || im_extract_band( in, t, 0 ) ) {
				im_close( out );
				return( NULL );
			}

			in = t;
		}
		else if( in->Bands > 3 && !allow_alpha ) {
			IMAGE *t = im_open_local( out, "conv:1", "p" );

			if( !t ||
				im_extract_bands( in, t, 0, 3 ) ) {
				im_close( out );
				return( NULL );
			}

			in = t;
		}
		else if( in->Bands > 4 && allow_alpha ) {
			IMAGE *t = im_open_local( out, "conv:1", "p" );

			if( !t ||
				im_extract_bands( in, t, 0, 4 ) ) {
				im_close( out );
				return( NULL );
			}

			in = t;
		}
	}

	/* Interpret the Type field for colorimetric images.
	 */
	if( in->Bands == 3 && in->BandFmt == IM_BANDFMT_SHORT && 
		in->Type == IM_TYPE_LABS ) {
		IMAGE *t = im_open_local( out, "conv:1", "p" );

		if( !t || im_LabS2LabQ( in, t ) ) {
			im_close( out );
			return( NULL );
		}

		in = t;
	}

	if( in->Coding == IM_CODING_LABQ ) {
		IMAGE *t = im_open_local( out, "conv:1", "p" );

		if( !t || im_LabQ2Lab( in, t ) ) {
			im_close( out );
			return( NULL );
		}

		in = t;
	}

	if( in->Coding != IM_CODING_NONE ) {
		im_close( out );
		return( NULL );
	}

	if( in->Bands == 3 && in->Type == IM_TYPE_LCH ) {
		IMAGE *t[2];

                if( im_open_local_array( out, t, 2, "conv-1", "p" ) ||
			im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) ||
			im_LCh2Lab( t[0], t[1] ) ) {
			im_close( out );
			return( NULL );
		}

		in = t[1];
	}

	if( in->Bands == 3 && in->Type == IM_TYPE_YXY ) {
		IMAGE *t[2];

                if( im_open_local_array( out, t, 2, "conv-1", "p" ) ||
			im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) ||
			im_Yxy2XYZ( t[0], t[1] ) ) {
			im_close( out );
			return( NULL );
		}

		in = t[1];
	}

	if( in->Bands == 3 && in->Type == IM_TYPE_UCS ) {
		IMAGE *t[2];

                if( im_open_local_array( out, t, 2, "conv-1", "p" ) ||
			im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) ||
			im_UCS2XYZ( t[0], t[1] ) ) {
			im_close( out );
			return( NULL );
		}

		in = t[1];
	}

	if( in->Bands == 3 && in->Type == IM_TYPE_LAB ) {
		IMAGE *t[2];

                if( im_open_local_array( out, t, 2, "conv-1", "p" ) ||
			im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) ||
			im_Lab2XYZ( t[0], t[1] ) ) {
			im_close( out );
			return( NULL );
		}

		in = t[1];
	}

	if( in->Bands == 3 && in->Type == IM_TYPE_XYZ ) {
		IMAGE *t[2];

                if( im_open_local_array( out, t, 2, "conv-1", "p" ) ||
			im_clip2fmt( in, t[0], IM_BANDFMT_FLOAT ) ||
			im_XYZ2disp( t[0], t[1], im_col_displays( 7 ) ) ) {
			im_close( out );
			return( NULL );
		}

		in = t[1];
	}

	/* Clip to uchar if not there already.
	 */
	if( in->BandFmt != IM_BANDFMT_UCHAR ) {
		IMAGE *t = im_open_local( out, "conv:1", "p" );

		if( !t || im_clip( in, t ) ) {
			im_close( out );
			return( NULL );
		}

		in = t;
	}

	if( im_copy( in, out ) ) {
		im_close( out );
		return( NULL );
	}

	return( out );
}

