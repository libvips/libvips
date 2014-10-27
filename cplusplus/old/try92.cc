/* 
 * compile with:
 *
 *      g++ -g -Wall try92.cc `pkg-config vips --cflags --libs`
 *
 */

#include <vips/vips.h>

enum VSteal {
	NOSTEAL = 0,
	STEAL = 1
};

class VObject
{
private:
	GObject *gobject; 

public:
	VObject( GObject *new_gobject, VSteal steal = STEAL ) : 
		gobject( new_gobject )
	{
		printf( "VObject constructor, obj = %p, steal = %d\n",
				new_gobject, steal ); 
		if( !steal ) {
			printf( "   reffing object\n" ); 
			g_object_ref( gobject ); 
		}
	}

	// copy constructor
	VObject( const VObject &vobject ) : 
		gobject( vobject.gobject )
	{
		printf( "VObject copy constructor, obj = %p\n", 
			gobject ); 
		g_object_ref( gobject );
		printf( "   reffing object\n" ); 
	}

	// assignment ... we must delete the old ref
	VObject &operator=( const VObject &a )
	{
		GObject *old_gobject;

		printf( "VObject assignment\n" );  
		printf( "   reffing %p\n", a.gobject ); 
		printf( "   unreffing %p\n", gobject ); 

		// delete the old ref at the end ... otherwise "a = a;" could
		// unref before reffing again 
		old_gobject = gobject;
		gobject = a.gobject;
		g_object_ref( gobject ); 
		g_object_unref( old_gobject );

		return( *this ); 
	}

	~VObject()
	{
		printf( "VObject destructor\n" );  
		printf( "   unreffing %p\n", gobject ); 
		
		g_object_unref( gobject ); 
	}

	GObject &operator*()
	{
		return( *gobject );
	}

	GObject *operator->()
	{    
		return( gobject );
	}

	GObject *get()
	{
		return( gobject ); 
	}

};

class VImage : VObject
{
public:
	VImage( VipsImage *image, VSteal steal = STEAL ) : 
		VObject( (GObject *) image, steal )
	{
	}

	VipsImage *get()
	{
		return( (VipsImage *) VObject::get() );
	}

};

int
main( int argc, char **argv )
{
	GOptionContext *context;
	GOptionGroup *main_group;
	GError *error = NULL;

	if( vips_init( argv[0] ) )
		vips_error_exit( NULL ); 

	context = g_option_context_new( "" ); 

	main_group = g_option_group_new( NULL, NULL, NULL, NULL, NULL );
	g_option_context_set_main_group( context, main_group );
	g_option_context_add_group( context, vips_get_option_group() );

	if( !g_option_context_parse( context, &argc, &argv, &error ) ) {
		if( error ) {
			fprintf( stderr, "%s\n", error->message );
			g_error_free( error );
		}

		vips_error_exit( NULL );
	}

	/*
	 
	VipsImage *in;
	VipsImage *out;

	if( !(in = vips_image_new_from_file( argv[1], NULL )) )
		vips_error_exit( NULL ); 

	if( vips_invert( in, &out, NULL ) ) 
		vips_error_exit( NULL ); 

	if( vips_image_write_to_file( out, argv[2], NULL ) )
		vips_error_exit( NULL ); 

	g_object_unref( in );
	g_object_unref( out );

	 */

	printf( "sizeof( VipsImage *) = %zd\n", sizeof( VipsImage *) ); 
	printf( "sizeof( VImage ) = %zd\n", sizeof( VImage ) ); 

{ 
	VipsImage *im;
       
	if( !(im = vips_image_new_from_file( argv[1], NULL )) )
		vips_error_exit( NULL ); 

	VImage in( im );
	VipsImage *out;

	if( vips_invert( in, &out, NULL ) ) 
		vips_error_exit( NULL ); 

	if( vips_image_write_to_file( out, argv[2], NULL ) )
		vips_error_exit( NULL ); 

	g_object_unref( out );
} 

	vips_shutdown();

        return( 0 );
}
