/* Read a Analyze file. Old-style header (so called 7.5 format).
 * 
 * 14/12/11
 * 	- just a compat stub now
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

#include <vips/vips.h>

static VipsFormatFlags
analyze_flags( const char *filename )
{
	return( vips_foreign_flags( "analyzeload", filename ) );
}

static int
isanalyze( const char *filename )
{
	return( vips_foreign_is_a( "analyzeload", filename ) );
}

int
im_analyze2vips( const char *filename, IMAGE *out )
{
	VipsImage *t;

	if( vips_analyzeload( filename, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static const char *analyze_suffs[] = { ".img", ".hdr", NULL };

typedef VipsFormat VipsFormatAnalyze;
typedef VipsFormatClass VipsFormatAnalyzeClass;

static void
vips_format_analyze_class_init( VipsFormatAnalyzeClass *class )
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsFormatClass *format_class = (VipsFormatClass *) class;

	object_class->nickname = "analyze";
	object_class->description = _( "Analyze 6.0" );

	format_class->is_a = isanalyze;
	format_class->header = im_analyze2vips;
	format_class->load = im_analyze2vips;
	format_class->get_flags = analyze_flags;
	format_class->suffs = analyze_suffs;
}

static void
vips_format_analyze_init( VipsFormatAnalyze *object )
{
}

G_DEFINE_TYPE( VipsFormatAnalyze, vips_format_analyze, VIPS_TYPE_FORMAT );

