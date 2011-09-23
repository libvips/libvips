/* Copy an image. 
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
 * 15/2/08
 * 	- added im__saveable_t ... so we can have CMYK JPEG write
 * 24/3/09
 * 	- added IM_CODING_RAD support
 * 28/1/10
 * 	- gtk-doc
 * 	- cleanups
 * 	- removed im_copy_from() and associated stuff
 * 	- added im_copy_native()
 * 28/11/10
 * 	- im_copy_set() now sets xoff / yoff again hmmm
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
#include <vips/internal.h>

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
	VipsType type, float xres, float yres, int xoffset, int yoffset,
	int bands, VipsBandFmt bandfmt, VipsCoding coding )
{
	/* Check args.
	 */
        if( im_check_coding_known( "im_copy", in ) ||
		im_piocheck( in, out ) )
		return( -1 );
	if( coding != IM_CODING_NONE && 
		coding != IM_CODING_LABQ &&
		coding != IM_CODING_RAD ) {
		im_error( "im_copy", "%s", 
			_( "coding must be NONE, LABQ or RAD" ) );
		return( -1 );
	}
	if( bandfmt < 0 || bandfmt > IM_BANDFMT_DPCOMPLEX ) {
		im_error( "im_copy", _( "bandfmt must be in range [0,%d]" ),
			IM_BANDFMT_DPCOMPLEX );
		return( -1 );
	}

	if( im_cp_desc( out, in ) )
		return( -1 );
	out->Type = type;
	out->Xres = xres;
	out->Yres = yres;
	out->Xoffset = xoffset;
	out->Yoffset = yoffset;
	out->Bands = bands;
	out->BandFmt = bandfmt;
	out->Coding = coding;

	/* Sanity check: we (may) have changed bytes-per-pixel since we've
	 * changed Bands and BandFmt ... bad!
	 */
	if( IM_IMAGE_SIZEOF_PEL( in ) != IM_IMAGE_SIZEOF_PEL( out ) ) {
		im_error( "im_copy", "%s", _( "sizeof( pixel ) has changed" ) );
		return( -1 );
	}

	/* Generate!
	 */
	if( im_demand_hint( out, IM_THINSTRIP, in, NULL ) ||
		im_generate( out, 
			im_start_one, copy_gen, im_stop_one, in, NULL ) )
		return( -1 );

	return( 0 );
}

/**
 * im_copy_set:
 * @in: input image
 * @out: output image
 * @type: new VipsType to set
 * @xres: new Xres to set
 * @yres: new Yres to set
 * @xoffset: new Xoffset to set
 * @yoffset: new Yoffset to set
 *
 * Copy an image, changing informational header fields on the way.
 *
 * See also: im_copy().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_copy_set( IMAGE *in, IMAGE *out, 
	VipsType type, float xres, float yres, int xoffset, int yoffset )
{
	return( im_copy_set_all( in, out, 
		type, xres, yres, xoffset, yoffset,
		in->Bands, in->BandFmt, in->Coding ) );
}

/**
 * im_copy_morph:
 * @in: input image
 * @out: output image
 * @bands: new number of bands
 * @bandfmt: new band format
 * @coding: new coding
 *
 * Copy an image, changing header fields which alter pixel addressing. The
 * pixel data itself is unchanged, this operation just changes the header
 * fields. 
 *
 * If you change the header fields such that the sizeof() a pixel changes,
 * you'll get an error.
 *
 * See also: im_copy().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_copy_morph( IMAGE *in, IMAGE *out, 
	int bands, VipsBandFmt bandfmt, VipsCoding coding )
{
	return( im_copy_set_all( in, out, 
		in->Type, in->Xres, in->Yres, 0, 0,
		bands, bandfmt, coding ) );
}

/**
 * im_copy:
 * @in: input image
 * @out: output image
 *
 * Copy an image. VIPS copies images by copying pointers, so this operation is
 * fast, even for very large images.
 *
 * See also: im_copy(), im_copy_set(), im_copy_morph().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_copy( IMAGE *in, IMAGE *out )
{
	return( im_copy_set( in, out, 
		in->Type, in->Xres, in->Yres, 0, 0 ) );
}

/**
 * im_copy_set_meta:
 * @in: input image
 * @out: output image
 * @field: metadata field to set
 * @value: value to set for the field
 *
 * Copy an image, changing a metadata field. You can use this to, for example,
 * update the ICC profile attached to an image.
 *
 * See also: im_copy().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_copy_set_meta( IMAGE *in, IMAGE *out, const char *field, GValue *value )
{
	if( im_copy( in, out ) )
		return( 1 );
	im_meta_set( out, field, value );

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

/**
 * im_copy_swap:
 * @in: input image
 * @out: output image
 *
 * Copy an image, swapping byte order between little and big endian. This
 * really does change image pixels and does not just alter the header.
 *
 * See also: im_copy(), im_amiMSBfirst(), im_isMSBfirst().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_copy_swap( IMAGE *in, IMAGE *out )
{
        if( im_piocheck( in, out ) ||
		im_check_uncoded( "im_copy_swap", in ) ||
		im_cp_desc( out, in ) )
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
		im_error( "im_copy_swap", "%s", _( "unsupported image type" ) );
		return( -1 );
	}

	return( 0 );
}

/**
 * im_copy_native:
 * @in: input image
 * @out: output image
 * @is_msb_first: %TRUE if @in is in most-significant first form
 *
 * Copy an image to native order, that is, the order for the executing
 * program.
 *
 * See also: im_copy_swap(), im_amiMSBfirst().
 *
 * Returns: 0 on success, -1 on error.
 */
int
im_copy_native( IMAGE *in, IMAGE *out, gboolean is_msb_first )
{
	if( is_msb_first != im_amiMSBfirst() )
		return( im_copy_swap( in, out ) );
	else
		return( im_copy( in, out ) );
}

/* Convert to a saveable format. 
 *
 * im__saveable_t gives the general type of image
 * we make: vanilla 1/3 bands (eg. PPM), with an optional alpha (eg. PNG), or
 * with CMYK as an option (eg. JPEG). 
 *
 * format_table[] says how to convert each input format. 
 *
 * Need to im_close() the result IMAGE.
 */
IMAGE *
im__convert_saveable( IMAGE *in, 
	im__saveable_t saveable, int format_table[10] ) 
{
	IMAGE *out;

	if( !(out = im_open( "convert-for-save", "p" )) )
		return( NULL );

	/* If this is an IM_CODING_LABQ, we can go straight to RGB.
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

	/* If this is an IM_CODING_RAD, we go to float RGB or XYZ. We should
	 * probably un-gamma-correct the RGB :(
	 */
	if( in->Coding == IM_CODING_RAD ) {
		IMAGE *t;

		if( !(t = im_open_local( out, "conv:1", "p" )) || 
			im_rad2float( in, t ) ) {
			im_close( out );
			return( NULL );
		}

		in = t;
	}

	/* Get the bands right. 
	 */
	if( in->Coding == IM_CODING_NONE ) {
		if( in->Bands == 2 && saveable != IM__RGBA ) {
			IMAGE *t = im_open_local( out, "conv:1", "p" );

			if( !t || im_extract_band( in, t, 0 ) ) {
				im_close( out );
				return( NULL );
			}

			in = t;
		}
		else if( in->Bands > 3 && saveable == IM__RGB ) {
			IMAGE *t = im_open_local( out, "conv:1", "p" );

			if( !t ||
				im_extract_bands( in, t, 0, 3 ) ) {
				im_close( out );
				return( NULL );
			}

			in = t;
		}
		else if( in->Bands > 4 && 
			(saveable == IM__RGB_CMYK || saveable == IM__RGBA) ) {
			IMAGE *t = im_open_local( out, "conv:1", "p" );

			if( !t ||
				im_extract_bands( in, t, 0, 4 ) ) {
				im_close( out );
				return( NULL );
			}

			in = t;
		}

		/* Else we have saveable IM__ANY and we don't chop bands down.
		 */
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

	/* Cast to the output format.
	 */
	{
		IMAGE *t = im_open_local( out, "conv:1", "p" );

		if( !t || im_clip2fmt( in, t, format_table[in->BandFmt] ) ) {
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
