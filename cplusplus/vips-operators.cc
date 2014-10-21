VImage VImage::add( VImage in2, ... )
	throw( VError )
{
	va_list ap;
	VImage out; 
	int result;

	va_start( ap, in2 );
	result = call_split( "add", ap, this, in2, &out );
	va_end( ap );

	if( result )
		VError();

	return( out );
}
