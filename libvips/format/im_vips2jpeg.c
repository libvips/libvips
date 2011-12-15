/* Convert 8-bit VIPS images to/from JPEG.
 *
 * 30/11/11
 * 	- now just a stub calling the new system
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
#define DEBUG_VERBOSE
#define DEBUG
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

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

/* Kept for back compat while we swap the rest of VipsFormat to the new
 * system.
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

int
im_vips2jpeg( IMAGE *in, const char *filename )
{
	int qfac = 75; 

	/* profile has to default to NULL, meaning "no param". If we default
	 * to "none" we will not attach the profile from the metadata.
	 */
	char *profile = NULL;

	char *p, *q;

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char buf[FILENAME_MAX];

	/* Parse mode from filename.
	 */
	im_filename_split( filename, name, mode );
	strcpy( buf, mode ); 
	p = &buf[0];
	if( (q = im_getnextoption( &p )) ) {
		if( strcmp( q, "" ) != 0 )
			qfac = atoi( mode );
	}
	if( (q = im_getnextoption( &p )) ) {
		if( strcmp( q, "" ) != 0 ) 
			profile = q;
	}
	if( (q = im_getnextoption( &p )) ) {
		im_error( "im_vips2jpeg", 
			_( "unknown extra options \"%s\"" ), q );
		return( -1 );
	}

	return( vips_jpegsave( in, name, 
		"Q", qfac, "profile", profile, NULL ) );
}

int
im_vips2bufjpeg( IMAGE *in, IMAGE *out, int qfac, char **obuf, int *olen )
{
	size_t len;

	if( vips_jpegsave_buffer( in, (void **) obuf, &len, "Q", qfac, NULL ) )
		return( -1 );
	im_add_callback( out, "close", 
		(im_callback_fn) vips_free, obuf, NULL ); 

	if( olen )
		*olen = len;

	return( 0 );
}

int
im_vips2mimejpeg( IMAGE *in, int qfac )
{
	return( vips_jpegsave_mime( in, "Q", qfac, NULL ) ); 
}
