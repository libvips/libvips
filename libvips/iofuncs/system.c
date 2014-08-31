/* vips_system(): run a command on an image
 *
 * 7/3/00 JC
 *	- hacked it in
 * 21/10/02 JC
 *	- use mktemp() if mkstemp() is not available
 * 10/3/03 JC
 *	- out can be NULL
 * 23/12/04
 *	- use g_mkstemp()
 * 8/9/09
 * 	- add .v suffix (thanks Roland)
 * 	- use vipsbuf
 * 	- rewrite to make it simpler
 * 2/2/10
 * 	- gtkdoc
 * 4/6/13
 * 	- redo as a class
 * 	- input and output images are now optional
 * 3/5/14
 * 	- switch to g_spawn_command_line_sync() from popen() ... helps stop
 * 	  stray command-windows on Windows
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <vips/vips.h>
#include <vips/internal.h>

typedef struct _VipsSystem {
	VipsOperation parent_instance;

	VipsArrayImage *in;
	VipsImage *out;
	char *cmd_format;
	char *in_format;
	char *out_format;
	char *log;

	/* Array of names we wrote the input images to.
	 */
	char **in_name;

	char *out_name;

} VipsSystem;

typedef VipsOperationClass VipsSystemClass;

G_DEFINE_TYPE( VipsSystem, vips_system, VIPS_TYPE_OPERATION );

static void
vips_system_dispose( GObject *gobject )
{
	VipsSystem *system = (VipsSystem *) gobject;

	if( system->in_name ) {
		int i;

		for( i = 0; i < VIPS_AREA( system->in )->n; i++ ) { 
			g_unlink( system->in_name[i] );
			VIPS_FREE( system->in_name[i] );
		}
	}

	VIPS_FREE( system->out_name );

	G_OBJECT_CLASS( vips_system_parent_class )->dispose( gobject );
}

static int
vips_system_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsSystem *system = (VipsSystem *) object;

	int i;

	char cmd[VIPS_PATH_MAX];

	char *p;
	char *std_output;
	char *std_error;
	int result;
	GError *error = NULL;

	if( VIPS_OBJECT_CLASS( vips_system_parent_class )->build( object ) )
		return( -1 );

	/* Write the input images to files. We must always make copies of the
	 * files, even if this image is a disc file already, in case the 
	 * command needs a different format.
	 */
	if( system->in ) { 
		char *in_format = system->in_format ? 
			system->in_format : "%s.tif";
		int n;
		VipsImage **in = vips_array_image_get( system->in, &n ); 

		if( !(system->in_name = VIPS_ARRAY( object, n, char * )) )
			return( -1 ); 
		memset( system->in_name, 0, n * sizeof( char * ) ); 
		for( i = 0; i < n; i++ ) { 
			if( !(system->in_name[i] = 
				vips__temp_name( in_format )) )
				return( -1 );
			if( vips_image_write_to_file( in[i], 
				system->in_name[i], NULL ) ) 
				return( -1 );
		}
	}

	/* Make the output filename.
	 */
	if( system->out_format &&
		!(system->out_name = vips__temp_name( system->out_format )) )
		return( -1 ); 

	vips_strncpy( cmd, system->cmd_format, VIPS_PATH_MAX );
	if( system->in ) 
		for( i = 0; i < VIPS_AREA( system->in )->n; i++ ) 
			if( vips__substitute( class->nickname, 
				cmd, VIPS_PATH_MAX, system->in_name[i] ) )
				return( -1 ); 
	if( system->out_name &&
		vips__substitute( class->nickname, 
			cmd, VIPS_PATH_MAX, system->out_name ) )
		return( -1 ); 

	/* Swap all "%%" in the string for a single "%". We need this for
	 * compatibility with older printf-based vips_system()s which
	 * needed a double %%.
	 */
	for( p = cmd; *p; p++ )
		if( p[0] == '%' &&
			p[1] == '%' )
			memmove( p, p + 1, strlen( p ) );

	if( !g_spawn_command_line_sync( cmd, 
		&std_output, &std_error, &result, &error ) ||
		result ) {
		if( error ) {
			vips_error( class->nickname, "%s", error->message );
			g_error_free( error );
		}
		if( std_error ) {
			vips__chomp( std_error ); 
			if( strcmp( std_error, "" ) != 0 )
				vips_error( class->nickname, 
					"error output: %s", std_error );
			VIPS_FREE( std_error );
		}
		if( std_output ) {
			vips__chomp( std_output ); 
			if( strcmp( std_output, "" ) != 0 )
				vips_error( class->nickname, 
					"output: %s", std_output );
			VIPS_FREE( std_output );
		}
		vips_error_system( result, class->nickname, 
			_( "command \"%s\" failed" ), cmd ); 

		return( -1 ); 
	}

	if( std_error ) {
		vips__chomp( std_error ); 
		if( strcmp( std_error, "" ) != 0 )
			vips_warn( class->nickname, 
				_( "stderr output: %s" ), std_error ); 
	}
	if( std_output ) {
		vips__chomp( std_output ); 
		g_object_set( system, "log", std_output, NULL ); 
	}

	VIPS_FREE( std_output );
	VIPS_FREE( std_error );

	if( system->out_name ) {
		VipsImage *out; 

		if( !(out = vips_image_new_from_file( system->out_name, 
			NULL )) )
			return( -1 );
		vips_image_set_delete_on_close( out, TRUE );
		g_object_set( system, "out", out, NULL ); 
	}

	return( 0 );
}

static void
vips_system_class_init( VipsSystemClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );
	VipsOperationClass *operation_class = VIPS_OPERATION_CLASS( class );

	gobject_class->dispose = vips_system_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "system";
	vobject_class->description = _( "run an external command" );
	vobject_class->build = vips_system_build;

	/* Commands can have side-effects, so don't cache them. 
	 */
	operation_class->flags = VIPS_OPERATION_NOCACHE;

	VIPS_ARG_BOXED( class, "in", 0, 
		_( "Input" ), 
		_( "Array of input images" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSystem, in ),
		VIPS_TYPE_ARRAY_IMAGE );

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output image" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT, 
		G_STRUCT_OFFSET( VipsSystem, out ) );

	VIPS_ARG_STRING( class, "cmd_format", 2, 
		_( "Command" ), 
		_( "Command to run" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsSystem, cmd_format ),
		NULL );

	VIPS_ARG_STRING( class, "in_format", 2, 
		_( "Input format" ), 
		_( "Format for input filename" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSystem, in_format ),
		NULL );

	VIPS_ARG_STRING( class, "out_format", 2, 
		_( "Output format" ), 
		_( "Format for output filename" ),
		VIPS_ARGUMENT_OPTIONAL_INPUT,
		G_STRUCT_OFFSET( VipsSystem, out_format ),
		NULL );

	VIPS_ARG_STRING( class, "log", 2, 
		_( "Log" ), 
		_( "Command log" ),
		VIPS_ARGUMENT_OPTIONAL_OUTPUT,
		G_STRUCT_OFFSET( VipsSystem, log ),
		NULL );

}

static void
vips_system_init( VipsSystem *system )
{
}

/**
 * vips_system:
 * @cmd_format: command to run
 * @...: %NULL-terminated list of optional named arguments
 *
 * Optional arguments:
 *
 * @in: array of input images
 * @out: output image
 * @in_format: write input files like this
 * @out_format: write output filename like this
 * @log: stdout of command is returned here
 *
 * vips_system() runs a command, optionally passing a set of images in and 
 * optionally getting an image back. The command's stdout is returned in @log. 
 *
 * First, if @in is set, the array of images are written to files. See
 * vips_image_new_temp_file() to see how temporary files are created. 
 * If @in_format is
 * something like &percnt;s.png, the file will be written in PNG format. By
 * default, @in_format is &percnt;s.tif. 
 *
 * If @out_format is set, an output filename is formed in the same way.
 *
 * The command string to run is made by substituting the first set of &percnt;s 
 * in @cmd_format for the names of the input files, if @in is set, and then 
 * the next &percnt;s for the output filename, if @out_format is set. 
 * You can put a number between the &percnt; and the s to change the order 
 * in which the substitution occurs.
 *
 * The command is executed with popen() and the output captured in @log. 
 *
 * After the command finishes, if @out_format is set, the output image is
 * opened and returned in @out. 
 * Closing @out image will automatically delete the output file.
 *
 * Finally the input images are deleted. 
 *
 * For example, this call will run the ImageMagick convert program on an
 * image, using JPEG files to pass images into and out of the convert command.
 *
 * |[
 * VipsArrayImage *in;
 * VipsImage *out;
 * char *log;
 *
 * if (vips_system ("convert %s -swirl 45 %s",
 * 	"in", in, 
 * 	"out", &out, 
 *   	"in_format", "%s.jpg", 
 *   	"out_format", "%s.jpg", 
 *   	"log", &log,
 *   	NULL))
 *   	error ...
 * ]|
 *
 * Returns: 0 on success, -1 on failure. 
 */
int
vips_system( const char *cmd_format, ... )
{
	va_list ap;
	int result;

	va_start( ap, cmd_format );
	result = vips_call_split( "system", ap, cmd_format );
	va_end( ap );

	return( result );
}
