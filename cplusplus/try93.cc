/* 
 * compile with:
 *
 *      g++ -g -Wall try93.cc `pkg-config vips --cflags --libs`
 *
 */

#include <list>
#include <string>
#include <iosfwd>
#include <exception>

#include <vips/vips.h>
#include <vips/debug.h>

class VError : public std::exception {
	std::string _what;

public:
	VError( std::string what ) : _what( what ) {}
	VError() : _what( vips_error_buffer() ) {}
	virtual ~VError() throw() {}

	// Extract string
	virtual const char *what() const throw() { return _what.c_str(); }
	void ostream_print( std::ostream & ) const;
};

inline std::ostream &operator<<( std::ostream &file, const VError &err )
{
	err.ostream_print( file );
	return( file );
}

void VError::ostream_print( std::ostream &file ) const
{
	file << _what;
}

enum VSteal {
	NOSTEAL = 0,
	STEAL = 1
};

class VObject
{
private:
	// can be NULL, see eg. VObject()
	VipsObject *vobject; 

public:
	VObject( VipsObject *new_vobject, VSteal steal = STEAL ) : 
		vobject( new_vobject )
	{
		// we allow NULL init, eg. "VImage a;"
		g_assert( !new_vobject ||
			VIPS_IS_OBJECT( new_vobject ) ); 

		printf( "VObject constructor, obj = %p, steal = %d\n",
			new_vobject, steal ); 
		if( new_vobject ) { 
			printf( "   obj " ); 
			vips_object_print_name( VIPS_OBJECT( new_vobject ) );
			printf( "\n" ); 
		}
		if( !steal ) {
			printf( "   reffing object\n" ); 
			g_object_ref( vobject ); 
		}
	}

	VObject() :
		vobject( 0 )
	{
	}

	// copy constructor 
	VObject( const VObject &a ) : 
		vobject( a.vobject )
	{
		g_assert( VIPS_IS_OBJECT( a.vobject ) ); 

		printf( "VObject copy constructor, obj = %p\n", 
			vobject ); 
		g_object_ref( vobject );
		printf( "   reffing object\n" ); 
	}

	// assignment ... we must delete the old ref
	// old can be NULL, new must not be NULL
	VObject &operator=( const VObject &a )
	{
		VipsObject *old_vobject;

		printf( "VObject assignment\n" );  
		printf( "   reffing %p\n", a.vobject ); 
		printf( "   unreffing %p\n", vobject ); 

		g_assert( !vobject ||
			VIPS_IS_OBJECT( vobject ) ); 
		g_assert( a.vobject &&
			VIPS_IS_OBJECT( a.vobject ) ); 

		// delete the old ref at the end ... otherwise "a = a;" could
		// unref before reffing again 
		old_vobject = vobject;
		vobject = a.vobject;
		g_object_ref( vobject ); 
		if( old_vobject )
			g_object_unref( old_vobject );

		return( *this ); 
	}

	// this mustn't be virtual: we want this class to only be a pointer,
	// no vtable allowed
	~VObject()
	{
		printf( "VObject destructor\n" );  
		printf( "   unreffing %p\n", vobject ); 

		g_assert( !vobject ||
			VIPS_IS_OBJECT( vobject ) ); 
		
		if( vobject ) 
			g_object_unref( vobject ); 
	}

	VipsObject *get_object()
	{
		g_assert( !vobject ||
			VIPS_IS_OBJECT( vobject ) ); 

		return( vobject ); 
	}

};

class VImage; 
class VOption; 

class VOption
{
private:
	struct Pair {
		const char *name;

		// the thing we pass to VipsOperation
		GValue value;

		// an input or output parameter ... we guess the direction
		// from the arg to set()
		bool input; 

		// we need to box and unbox VImage ... keep a pointer to the
		// VImage from C++ here
		VImage *vimage;

		Pair( const char *name ) : 
			name( name ), input( false ), vimage( 0 )
		{
			G_VALUE_TYPE( &value ) = 0;
		}

		~Pair()
		{
			g_value_unset( &value );
		}
	};

	std::list<Pair *> options;

public:
	VOption()
	{
	}

	virtual ~VOption();

	VOption *set( const char *name, const char *value );
	VOption *set( const char *name, int value );
	VOption *set( const char *name, VImage value );
	VOption *set( const char *name, VImage *value );

	void set_operation( VipsOperation *operation );
	void get_operation( VipsOperation *operation );

};

class VImage : VObject
{
public:
	VImage( VipsImage *image, VSteal steal = STEAL ) : 
		VObject( (VipsObject *) image, steal )
	{
	}

	// an empty (NULL) VImage, eg. "VImage a;"
	VImage() :
		VObject( 0 )
	{
	}

	VipsImage *get_image()
	{
		return( (VipsImage *) VObject::get_object() );
	}

	static VOption *option()
	{
		return( new VOption() );
	}

	static void call_option_string( const char *operation_name, 
		const char *option_string, VOption *options = 0 ) 
		throw( VError );
	static void call( const char *operation_name, VOption *options = 0 ) 
		throw( VError );

	static VImage new_from_file( const char *name, VOption *options = 0 )
		throw( VError );

	void write_to_file( const char *name, VOption *options = 0 )
		throw( VError );

	VImage invert( VOption *options = 0 )
		throw( VError );

};

VOption::~VOption()
{
	std::list<Pair *>::iterator i;

	for( i = options.begin(); i != options.end(); i++ ) 
		delete *i;
}

VOption *VOption::set( const char *name, const char *value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, G_TYPE_STRING );
	g_value_set_string( &pair->value, value );
	options.push_back( pair );

	return( this );
}

VOption *VOption::set( const char *name, int value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, G_TYPE_INT );
	g_value_set_int( &pair->value, value );
	options.push_back( pair );

	return( this );
}

VOption *VOption::set( const char *name, VImage value )
{
	Pair *pair = new Pair( name );

	pair->input = true;
	g_value_init( &pair->value, VIPS_TYPE_IMAGE );
	// we need to unbox
	g_value_set_object( &pair->value, value.get_image() );
	options.push_back( pair );

	return( this );
}

VOption *VOption::set( const char *name, VImage *value )
{
	Pair *pair = new Pair( name );

	// note where we will write the VImage on success
	pair->input = false;
	pair->vimage = value;
	g_value_init( &pair->value, VIPS_TYPE_IMAGE );

	options.push_back( pair );

	return( this );
}

// walk the options and set props on the operation 
void VOption::set_operation( VipsOperation *operation )
{
	std::list<Pair *>::iterator i;

	for( i = options.begin(); i != options.end(); i++ ) 
		if( (*i)->input ) {
			printf( "set_operation: " );
			vips_object_print_name( VIPS_OBJECT( operation ) );
			char *str_value = 
				g_strdup_value_contents( &(*i)->value );
			printf( ".%s = %s\n", (*i)->name, str_value );
			g_free( str_value );

			g_object_set_property( G_OBJECT( operation ),
				(*i)->name, &(*i)->value );
		}
}

// walk the options and do any processing needed for output objects
void VOption::get_operation( VipsOperation *operation )
{
	std::list<Pair *>::iterator i;

	for( i = options.begin(); i != options.end(); i++ ) 
		if( not (*i)->input ) {
			g_object_get_property( G_OBJECT( operation ),
				(*i)->name, &(*i)->value );

			printf( "get_operation: " );
			vips_object_print_name( VIPS_OBJECT( operation ) );
			char *str_value = 
				g_strdup_value_contents( &(*i)->value );
			printf( ".%s = %s\n", (*i)->name, str_value );
			g_free( str_value );

			// rebox object
			VipsImage *image = VIPS_IMAGE( 
				g_value_get_object( &(*i)->value ) );  
			if( (*i)->vimage )
				*((*i)->vimage) = VImage( image ); 
		}
}

void VImage::call_option_string( const char *operation_name, 
	const char *option_string, VOption *options ) 
	throw( VError )
{
	VipsOperation *operation;

	VIPS_DEBUG_MSG( "vips_call_by_name: starting for %s ...\n", 
		operation_name );

	if( !(operation = vips_operation_new( operation_name )) ) {
		if( options )
			delete options;
		throw( VError() ); 
	}

	/* Set str options before vargs options, so the user can't 
	 * override things we set deliberately.
	 */
	if( option_string &&
		vips_object_set_from_string( VIPS_OBJECT( operation ), 
			option_string ) ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		g_object_unref( operation ); 
		delete options; 
		throw( VError() ); 
	}

	if( options )
		options->set_operation( operation );

	/* Build from cache.
	 */
	if( vips_cache_operation_buildp( &operation ) ) {
		vips_object_unref_outputs( VIPS_OBJECT( operation ) );
		delete options; 
		throw( VError() ); 
	}

	/* Walk args again, writing output.
	 */
	if( options )
		options->get_operation( operation );

	/* The operation we have built should now have been reffed by 
	 * one of its arguments or have finished its work. Either 
	 * way, we can unref.
	 */
	g_object_unref( operation );
}

void VImage::call( const char *operation_name, VOption *options ) 
	throw( VError )
{
	call_option_string( operation_name, NULL, options ); 
}

VImage VImage::new_from_file( const char *name, VOption *options )
	throw( VError )
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

	call_option_string( operation_name, option_string,
		(options ? options : VImage::option())-> 
			set( "filename", filename )->
			set( "out", &out ) );

	return( out ); 
}

void VImage::write_to_file( const char *name, VOption *options )
	throw( VError )
{
	char filename[VIPS_PATH_MAX];
	char option_string[VIPS_PATH_MAX];
	const char *operation_name;

	vips__filename_split8( name, filename, option_string );
	if( !(operation_name = vips_foreign_find_save( filename )) ) {
		delete options; 
		throw VError(); 
	}

	call_option_string( operation_name, option_string, 
		(options ? options : VImage::option())-> 
			set( "in", *this )->
			set( "filename", filename ) );
}

VImage VImage::invert( VOption *options )
	throw( VError )
{
	VImage out;

	call( "invert", 
		(options ? options : VImage::option())-> 
			set( "in", *this )->
			set( "out", &out ) );

	return( out );
}

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

	//out = in.invert();

	//out.write_to_file( argv[2] );
}

	vips_shutdown();

        return( 0 );
}
