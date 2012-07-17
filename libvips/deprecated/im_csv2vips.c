/* Read a csv file.
 * 
 * 16/12/11
 * 	- just a stub
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

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <vips/vips.h>

int
im_csv2vips( const char *filename, IMAGE *out )
{
	/* Read options.
	 */
	int start_skip = 0;
	char *whitespace = " ";
	char *separator = ";,\t";
	int lines = -1;

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	char *p, *q, *r;
	VipsImage *t;

	/* Parse mode string.
	 */
	im_filename_split( filename, name, mode );
	p = &mode[0];
	while( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "ski", q ) && (r = im_getsuboption( q )) )
			start_skip = atoi( r );
		else if( im_isprefix( "whi", q ) && (r = im_getsuboption( q )) )
			whitespace = r;
		else if( im_isprefix( "sep", q ) && (r = im_getsuboption( q )) )
			separator = r;
		else if( im_isprefix( "lin", q ) && (r = im_getsuboption( q )) )
			lines = atoi( r );
	}

	if( vips_csvload( name, &t, 
		"skip", start_skip,
		"lines", lines,
		"whitespace", whitespace,
		"separator", separator,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static const char *csv_suffs[] = { ".csv", NULL };

/* csv format adds no new members.
 */
typedef VipsFormat VipsFormatCsv;
typedef VipsFormatClass VipsFormatCsvClass;

static void
vips_format_csv_class_init( VipsFormatCsvClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "csv";
	object_class->description = _( "CSV" );

	format_class->load = im_csv2vips;
	format_class->save = im_vips2csv;
	format_class->suffs = csv_suffs;
}

static void
vips_format_csv_init( VipsFormatCsv *object )
{
}

G_DEFINE_TYPE( VipsFormatCsv, vips_format_csv, VIPS_TYPE_FORMAT );
