
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

