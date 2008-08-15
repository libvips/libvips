/* VIPS function dispatch tables for image format load/save.
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

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

static int
jpeg2vips_vec( im_object *argv )
{
	char *in = argv[0];
	IMAGE *out = argv[1];

	if( im_jpeg2vips( in, out ) )
		return( -1 );

	return( 0 );
}

static im_arg_desc jpeg2vips_args[] = {
	IM_INPUT_STRING( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

static im_function jpeg2vips_desc = {
	"im_jpeg2vips",			/* Name */
	"convert from jpeg",		/* Description */
	0,				/* Flags */
	jpeg2vips_vec,			/* Dispatch function */
	IM_NUMBER( jpeg2vips_args ), 	/* Size of arg list */
	jpeg2vips_args 			/* Arg list */
};

static int
vips2jpeg_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	char *out = argv[1];

	if( im_vips2jpeg( in, out ) )
		return( -1 );

	return( 0 );
}

static im_arg_desc vips2jpeg_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_STRING( "out" )
};

static im_function vips2jpeg_desc = {
	"im_vips2jpeg",			/* Name */
	"convert to jpeg",		/* Description */
	0,				/* Flags */
	vips2jpeg_vec,			/* Dispatch function */
	IM_NUMBER( vips2jpeg_args ), 	/* Size of arg list */
	vips2jpeg_args 			/* Arg list */
};

static int
vips2mimejpeg_vec( im_object *argv )
{
	IMAGE *in = argv[0];
	int qfac = *((int *) argv[1]);

	if( im_vips2mimejpeg( in, qfac ) )
		return( -1 );

	return( 0 );
}

static im_arg_desc vips2mimejpeg_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_INT( "qfac" )
};

static im_function vips2mimejpeg_desc = {
	"im_vips2mimejpeg",		/* Name */
	"convert to jpeg as mime type on stdout", /* Description */
	0,				/* Flags */
	vips2mimejpeg_vec,		/* Dispatch function */
	IM_NUMBER( vips2mimejpeg_args ), /* Size of arg list */
	vips2mimejpeg_args 		/* Arg list */
};

/* Args for vips2png.
 */
static im_arg_desc vips2png_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_STRING( "out" )
};

/* Call im_vips2png via arg vector.
 */
static int
vips2png_vec( im_object *argv )
{
	return( im_vips2png( argv[0], argv[1] ) );
}

/* Description of im_vips2png.
 */
static im_function vips2png_desc = {
	"im_vips2png", 			/* Name */
	"convert VIPS image to PNG file", /* Description */
	0,
	vips2png_vec, 			/* Dispatch function */
	IM_NUMBER( vips2png_args ), 	/* Size of arg list */
	vips2png_args 			/* Arg list */
};

/* Args for png2vips.
 */
static im_arg_desc png2vips_args[] = {
	IM_INPUT_STRING( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_png2vips via arg vector.
 */
static int
png2vips_vec( im_object *argv )
{
	return( im_png2vips( argv[0], argv[1] ) );
}

/* Description of im_png2vips.
 */
static im_function png2vips_desc = {
	"im_png2vips", 			/* Name */
	"convert PNG file to VIPS image", /* Description */
	0,
	png2vips_vec, 			/* Dispatch function */
	IM_NUMBER( png2vips_args ), 	/* Size of arg list */
	png2vips_args 			/* Arg list */
};

/* Args for exr2vips.
 */
static im_arg_desc exr2vips_args[] = {
	IM_INPUT_STRING( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_exr2vips via arg vector.
 */
static int
exr2vips_vec( im_object *argv )
{
	return( im_exr2vips( argv[0], argv[1] ) );
}

/* Description of im_exr2vips.
 */
static im_function exr2vips_desc = {
	"im_exr2vips", 			/* Name */
	"convert an OpenEXR file to VIPS", /* Description */
	0,
	exr2vips_vec, 			/* Dispatch function */
	IM_NUMBER( exr2vips_args ), 	/* Size of arg list */
	exr2vips_args 			/* Arg list */
};

/* Args for vips2tiff.
 */
static im_arg_desc vips2tiff_args[] = {
	IM_INPUT_IMAGE( "in" ),
	IM_INPUT_STRING( "out" )
};

/* Call im_vips2tiff via arg vector.
 */
static int
vips2tiff_vec( im_object *argv )
{
	return( im_vips2tiff( argv[0], argv[1] ) );
}

/* Description of im_vips2tiff.
 */
static im_function vips2tiff_desc = {
	"im_vips2tiff", 		/* Name */
	"convert VIPS image to TIFF file", /* Description */
	0,
	vips2tiff_vec, 			/* Dispatch function */
	IM_NUMBER( vips2tiff_args ), 	/* Size of arg list */
	vips2tiff_args 			/* Arg list */
};

/* Args for magick2vips.
 */
static im_arg_desc magick2vips_args[] = {
	IM_INPUT_STRING( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_magick2vips via arg vector.
 */
static int
magick2vips_vec( im_object *argv )
{
	return( im_magick2vips( argv[0], argv[1] ) );
}

/* Description of im_magick2vips.
 */
static im_function magick2vips_desc = {
	"im_magick2vips", 		/* Name */
	"load file with libMagick", 	/* Description */
	0,
	magick2vips_vec, 		/* Dispatch function */
	IM_NUMBER( magick2vips_args ), 	/* Size of arg list */
	magick2vips_args 		/* Arg list */
};

/* Args for tiff2vips.
 */
static im_arg_desc tiff2vips_args[] = {
	IM_INPUT_STRING( "in" ),
	IM_OUTPUT_IMAGE( "out" )
};

/* Call im_tiff2vips via arg vector.
 */
static int
tiff2vips_vec( im_object *argv )
{
	return( im_tiff2vips( argv[0], argv[1] ) );
}

/* Description of im_tiff2vips.
 */
static im_function tiff2vips_desc = {
	"im_tiff2vips", 		/* Name */
	"convert TIFF file to VIPS image", /* Description */
	0,
	tiff2vips_vec, 			/* Dispatch function */
	IM_NUMBER( tiff2vips_args ), 	/* Size of arg list */
	tiff2vips_args 			/* Arg list */
};

static int
analyze2vips_vec( im_object *argv )
{
        const char *in = argv[0];
        IMAGE *out = argv[1];

        return( im_analyze2vips( in, out ) );
}

static im_arg_desc analyze2vips_arg_types[] = {
        IM_INPUT_STRING( "filename" ),
        IM_OUTPUT_IMAGE( "im" )
};

static im_function analyze2vips_desc = {
        "im_analyze2vips",          	/* Name */
        "read a file in analyze format",/* Description */
        0,                             	/* Flags */
        analyze2vips_vec,               /* Dispatch function */
        IM_NUMBER( analyze2vips_arg_types ),/* Size of arg list */
        analyze2vips_arg_types          /* Arg list */
};

static int
csv2vips_vec( im_object *argv )
{
        const char *in = argv[0];
        IMAGE *out = argv[1];

        return( im_csv2vips( in, out ) );
}

static im_arg_desc csv2vips_arg_types[] = {
        IM_INPUT_STRING( "filename" ),
        IM_OUTPUT_IMAGE( "im" )
};

static im_function csv2vips_desc = {
        "im_csv2vips",          	/* Name */
        "read a file in csv format",/* Description */
        0,                             	/* Flags */
        csv2vips_vec,               /* Dispatch function */
        IM_NUMBER( csv2vips_arg_types ),/* Size of arg list */
        csv2vips_arg_types          /* Arg list */
};

static int
vips2csv_vec( im_object *argv )
{
        IMAGE *in = argv[0];
        const char *filename = argv[1];

        return( im_vips2csv( in, filename ) );
}

static im_arg_desc vips2csv_arg_types[] = {
        IM_INPUT_IMAGE( "in" ),
        IM_INPUT_STRING( "filename" )
};

static im_function vips2csv_desc = {
        "im_vips2csv",          	/* Name */
        "write an image in csv format",	/* Description */
        0,                          	/* Flags */
        vips2csv_vec,               	/* Dispatch function */
        IM_NUMBER( vips2csv_arg_types ),/* Size of arg list */
        vips2csv_arg_types          	/* Arg list */
};

static int
ppm2vips_vec( im_object *argv )
{
        const char *in = argv[0];
        IMAGE *out = argv[1];

        return( im_ppm2vips( in, out ) );
}

static im_arg_desc ppm2vips_arg_types[] = {
        IM_INPUT_STRING( "filename" ),
        IM_OUTPUT_IMAGE( "im" )
};

static im_function ppm2vips_desc = {
        "im_ppm2vips",                  /* Name */
        "read a file in pbm/pgm/ppm format",     /* Description */
        0,                              /* Flags */
        ppm2vips_vec,                  	/* Dispatch function */
        IM_NUMBER( ppm2vips_arg_types ),/* Size of arg list */
        ppm2vips_arg_types              /* Arg list */
};

static int
vips2ppm_vec( im_object *argv )
{
        IMAGE *im = argv[0];
        const char *filename = argv[1];

        return( im_vips2ppm( im, filename ) );
}

static im_arg_desc vips2ppm_arg_types[] = {
        IM_INPUT_IMAGE( "im" ),
        IM_INPUT_STRING( "filename" )
};

static im_function vips2ppm_desc = {
        "im_vips2ppm",                  /* Name */
        "write a file in pbm/pgm/ppm format",     /* Description */
        0,                              /* Flags */
        vips2ppm_vec,                  	/* Dispatch function */
        IM_NUMBER( vips2ppm_arg_types ),/* Size of arg list */
        vips2ppm_arg_types              /* Arg list */
};

/* Package up all these functions.
 */
static im_function *list[] = {
	&csv2vips_desc,
	&jpeg2vips_desc,
	&magick2vips_desc,
	&png2vips_desc,
	&exr2vips_desc,
	&ppm2vips_desc,
	&analyze2vips_desc,
	&tiff2vips_desc,
	&vips2csv_desc,
	&vips2jpeg_desc,
	&vips2mimejpeg_desc,
	&vips2png_desc,
	&vips2ppm_desc,
	&vips2tiff_desc
};

/* Package of functions.
 */
im_package im__format = {
	"format",
	IM_NUMBER( list ),
	list
};
