/* vips7 compat stub for im_vips2tiff.c
 *
 * 4/12/11
 * 	- just a stub calling vips_tiffsave()
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

/* Turn on IM_REGION_ADDR() range checks, don't delete intermediates.
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>

int
im_vips2tiff( IMAGE *in, const char *filename )
{
	char *p, *q, *r;
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char buf[FILENAME_MAX];

	VipsForeignTiffCompression compression = 
		VIPS_FOREIGN_TIFF_COMPRESSION_NONE;
	int Q = 75; 
	VipsForeignTiffPredictor predictor = VIPS_FOREIGN_TIFF_PREDICTOR_NONE;
	char *profile = NULL;
	gboolean tile = FALSE; 
	int tile_width = 128;
	int tile_height = 128;
	gboolean pyramid = FALSE;
	gboolean squash = FALSE;
	VipsForeignTiffResunit resunit = VIPS_FOREIGN_TIFF_RESUNIT_CM; 
	double xres = in->Xres * 10.0;
	double yres = in->Yres * 10.0;
	gboolean bigtiff = FALSE;

	im_filename_split( filename, name, mode );
	strcpy( buf, mode ); 
	p = &buf[0];
	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "none", q ) ) 
			compression = VIPS_FOREIGN_TIFF_COMPRESSION_NONE;
		else if( im_isprefix( "packbits", q ) ) 
			compression = VIPS_FOREIGN_TIFF_COMPRESSION_PACKBITS;
		else if( im_isprefix( "ccittfax4", q ) ) 
			compression = VIPS_FOREIGN_TIFF_COMPRESSION_CCITTFAX4;
		else if( im_isprefix( "lzw", q ) ) {
			compression = VIPS_FOREIGN_TIFF_COMPRESSION_LZW;

			if( (r = im_getsuboption( q )) ) {
				int i;

				if( sscanf( r, "%d", &i ) != 1 ) {
					im_error( "im_vips2tiff",
						"%s", _( "bad predictor "
							"parameter" ) );
					return( -1 );
				}
				predictor = i;
			}
		}
		else if( im_isprefix( "deflate", q ) ) {
			compression = VIPS_FOREIGN_TIFF_COMPRESSION_DEFLATE;

			if( (r = im_getsuboption( q )) ) {
				int i;

				if( sscanf( r, "%d", &i ) != 1 ) {
					im_error( "im_vips2tiff",
						"%s", _( "bad predictor "
							"parameter" ) );
					return( -1 );
				}
				predictor = i;
			}
		}
		else if( im_isprefix( "jpeg", q ) ) {
			compression = VIPS_FOREIGN_TIFF_COMPRESSION_JPEG;

			if( (r = im_getsuboption( q )) ) 
				if( sscanf( r, "%d", &Q ) != 1 ) {
					im_error( "im_vips2tiff",
						"%s", _( "bad JPEG quality "
							"parameter" ) );
					return( -1 );
				}
		}
		else {
			im_error( "im_vips2tiff", _( "unknown compression mode "
				"\"%s\"\nshould be one of \"none\", "
				"\"packbits\", \"ccittfax4\", \"lzw\", "
				"\"deflate\" or \"jpeg\"" ), q );
			return( -1 );
		}
	}

	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "tile", q ) ) {
			tile = TRUE;

			if( (r = im_getsuboption( q )) ) {
				if( sscanf( r, "%dx%d", 
					&tile_width, &tile_height ) != 2 ) {
					im_error( "im_vips2tiff", "%s", 
						_( "bad tile sizes" ) );
					return( -1 );
				}
			}
		}
		else if( im_isprefix( "strip", q ) ) 
			tile = FALSE;
		else {
			im_error( "im_vips2tiff", _( "unknown layout mode "
				"\"%s\"\nshould be one of \"tile\" or "
				"\"strip\"" ), q );
			return( -1 );
		}
	}

	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "pyramid", q ) ) 
			pyramid = TRUE;
		else if( im_isprefix( "flat", q ) ) 
			pyramid = TRUE;
		else {
			im_error( "im_vips2tiff", _( "unknown multi-res mode "
				"\"%s\"\nshould be one of \"flat\" or "
				"\"pyramid\"" ), q );
			return( -1 );
		}
	}

	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "onebit", q ) ) 
			squash = TRUE;
		else if( im_isprefix( "manybit", q ) ) 
			squash = FALSE;
		else {
			im_error( "im_vips2tiff", _( "unknown format "
				"\"%s\"\nshould be one of \"onebit\" or "
				"\"manybit\"" ), q );
			return( -1 );
		}
	}

	if( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "res_cm", q ) ) {
			if( resunit == VIPS_FOREIGN_TIFF_RESUNIT_INCH ) {
				xres /= 2.54;
				yres /= 2.54;
			}
			resunit = VIPS_FOREIGN_TIFF_RESUNIT_CM;
		}
		else if( im_isprefix( "res_inch", q ) ) {
			if( resunit == VIPS_FOREIGN_TIFF_RESUNIT_CM ) {
				xres *= 2.54;
				yres *= 2.54;
			}
			resunit = VIPS_FOREIGN_TIFF_RESUNIT_INCH;
		}
		else {
			im_error( "im_vips2tiff", _( "unknown resolution unit "
				"\"%s\"\nshould be one of \"res_cm\" or "
				"\"res_inch\"" ), q );
			return( -1 );
		}

		if( (r = im_getsuboption( q )) ) {
			if( sscanf( r, "%lfx%lf", &xres, &yres ) != 2 ) {
				if( sscanf( r, "%lf", &xres ) != 1 ) {
					im_error( "im_vips2tiff", "%s", 
						_( "bad resolution values" ) );
					return( -1 );
				}

				yres = xres;
			}
		}
	}

	if( (q = im_getnextoption( &p )) && strcmp( q, "" ) != 0 ) 
		profile = im_strdup( NULL, q );

	if( (q = im_getnextoption( &p )) && strcmp( q, "8" ) == 0 ) 
		bigtiff = TRUE;

	if( (q = im_getnextoption( &p )) ) {
		im_error( "im_vips2tiff", 
			_( "unknown extra options \"%s\"" ), q );
		return( -1 );
	}

	if( vips_tiffsave( in, filename,
		"compression", compression,
		"Q", Q,
		"predictor", predictor,
		"profile", profile,
		"tile", tile,
		"tile_width", tile_width,
		"tile_height", tile_height,
		"pyramid", pyramid,
		"squash", squash,
		"resunit", resunit,
		"xres", xres,
		"yres", yres,
		"bigtiff", bigtiff,
		NULL ) )
		return( -1 );

	return( 0 );
}
