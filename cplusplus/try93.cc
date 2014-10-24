/* 
 * compile with:
 *
 *      g++ -g -Wall try93.cc `pkg-config vips --cflags --libs`
 *
 */

#include <list>

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

	GObject *get_object()
	{
		return( gobject ); 
	}

};

class VOption
{
private:
	struct Pair {
		const char *name;
		GValue value = {0, };

		Pair( const char *name ) : name( name )
		{
		}

		~Pair()
		{
			g_value_unset( &value )
		}
	}

	std::list<Pair *> options;

public:
	VOption()
	{
	}

	~VOption()
	{
		std::list<Pair *>::iterator i;

		for( i = options.begin(); i != options.end(); i++ ) 
			delete *i;
	}

	VOption set( const char *name, const char *value )
	{
		Pair *pair = new Pair( name );

		g_value_init( &pair->value, G_TYPE_STRING );
		g_value_set_string( &pair->value, value );
		options.push_back( pair );

		return( this );
	}

	VOption set( const char *name, int value )
	{
		Pair *pair = new Pair( name );

		g_value_init( &pair->value, G_TYPE_INT );
		g_value_set_int( &pair->value, value );
		options.push_back( pair );

		return( this );
	}

	VOption set( const char *name, VImage value )
	{
		Pair *pair = new Pair( name );

		g_value_init( &pair->value, G_TYPE_OBJECT );
		g_value_set_object( &pair->value, value );
		options.push_back( pair );

		return( this );
	}

	VOption set( const char *name, VImage *value )
	{
		Pair *pair = new Pair( name );

		g_value_init( &pair->value, G_TYPE_POINTER );
		g_value_set_pointer( &pair->value, value );
		options.push_back( pair );

		return( this );
	}

}

class VImage : VObject
{
public:
	VImage( VipsImage *image, VSteal steal = STEAL ) : 
		VObject( (GObject *) image, steal )
	{
	}

	VipsImage *get_image()
	{
		return( (VipsImage *) VObject::get_object() );
	}

	VImage::VOption *option()
	{
		return( new VOption() );
	}

	VImage new_from_file( const char *name, VOption *options = 0 )
	{
		char filename[VIPS_PATH_MAX];
		char option_string[VIPS_PATH_MAX];
		const char *operation_name;

		VImage out; 

		vips__filename_split8( name, filename, option_string );
		if( !(operation_name = vips_foreign_find_load( filename )) ) {
			delete options; 
			throw VError(); 
		}

		if( call_option_string( operation_name, option_string,
			options.set( "filename", filename ).
				set( "out", &out ) ) ) {
			delete options; 
			throw VError(); 
		}

		delete options; 
	}

	void write_to_file( const char *name, VOption *options = 0 )
	{
		char filename[VIPS_PATH_MAX];
		char option_string[VIPS_PATH_MAX];
		const char *operation_name;

		vips__filename_split8( name, filename, option_string );
		if( !(operation_name = vips_foreign_find_save( filename )) ) {
			delete options; 
			throw VError(); 
		}

		if( call_option_string( operation_name, option_string, 
			options.set( "in", this ).
				set( "filename", filename ) ) ) { 
			delete options; 
			throw VError(); 
		}

		delete options; 
	}

	VImage invert( VOption *options = 0 )
	{
		VImage out;

		if( call( "invert", 
			options.set( "in", this ).
				set( "out", &out ) ) ) {  
			delete options; 
			throw VError(); 
		}
		delete options; 

		return( out );
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
	VImage in = VImage::new_from_file( argv[1] ); 
	VImage out; 

	out = in.invert()

	out.write_to_file( argv[2] );
}

	vips_shutdown();

        return( 0 );
}
