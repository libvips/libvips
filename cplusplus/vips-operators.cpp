// bodies for vips operations
// Tue Jan  6 11:44:30 GMT 2015
// this file is generated automatically, do not edit!

void VImage::system( char * cmd_format , VOption *options )
    throw( VError )
{
    call( "system" ,
        (options ? options : VImage::option()) ->
            set( "cmd-format", cmd_format ) );
}

VImage VImage::add( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "add" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::subtract( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "subtract" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::multiply( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "multiply" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::divide( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "divide" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::relational( VImage right , VipsOperationRelational relational , VOption *options )
    throw( VError )
{
    VImage out;

    call( "relational" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) ->
            set( "relational", relational ) );

    return( out );
}

VImage VImage::remainder( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "remainder" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::boolean( VImage right , VipsOperationBoolean boolean , VOption *options )
    throw( VError )
{
    VImage out;

    call( "boolean" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) ->
            set( "boolean", boolean ) );

    return( out );
}

VImage VImage::math2( VImage right , VipsOperationMath2 math2 , VOption *options )
    throw( VError )
{
    VImage out;

    call( "math2" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) ->
            set( "math2", math2 ) );

    return( out );
}

VImage VImage::complex2( VImage right , VipsOperationComplex2 cmplx , VOption *options )
    throw( VError )
{
    VImage out;

    call( "complex2" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) ->
            set( "cmplx", cmplx ) );

    return( out );
}

VImage VImage::complexform( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "complexform" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::sum( std::vector<VImage> in , VOption *options )
    throw( VError )
{
    VImage out;

    call( "sum" ,
        (options ? options : VImage::option()) ->
            set( "in", in ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::invert( VOption *options )
    throw( VError )
{
    VImage out;

    call( "invert" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::linear( std::vector<double> a , std::vector<double> b , VOption *options )
    throw( VError )
{
    VImage out;

    call( "linear" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "a", a ) ->
            set( "b", b ) );

    return( out );
}

VImage VImage::math( VipsOperationMath math , VOption *options )
    throw( VError )
{
    VImage out;

    call( "math" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "math", math ) );

    return( out );
}

VImage VImage::abs( VOption *options )
    throw( VError )
{
    VImage out;

    call( "abs" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::sign( VOption *options )
    throw( VError )
{
    VImage out;

    call( "sign" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::round( VipsOperationRound round , VOption *options )
    throw( VError )
{
    VImage out;

    call( "round" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "round", round ) );

    return( out );
}

VImage VImage::relational_const( std::vector<double> c , VipsOperationRelational relational , VOption *options )
    throw( VError )
{
    VImage out;

    call( "relational_const" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "c", c ) ->
            set( "relational", relational ) );

    return( out );
}

VImage VImage::remainder_const( std::vector<double> c , VOption *options )
    throw( VError )
{
    VImage out;

    call( "remainder_const" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "c", c ) );

    return( out );
}

VImage VImage::boolean_const( std::vector<double> c , VipsOperationBoolean boolean , VOption *options )
    throw( VError )
{
    VImage out;

    call( "boolean_const" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "c", c ) ->
            set( "boolean", boolean ) );

    return( out );
}

VImage VImage::math2_const( std::vector<double> c , VipsOperationMath2 math2 , VOption *options )
    throw( VError )
{
    VImage out;

    call( "math2_const" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "c", c ) ->
            set( "math2", math2 ) );

    return( out );
}

VImage VImage::complex( VipsOperationComplex cmplx , VOption *options )
    throw( VError )
{
    VImage out;

    call( "complex" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "cmplx", cmplx ) );

    return( out );
}

VImage VImage::complexget( VipsOperationComplexget get , VOption *options )
    throw( VError )
{
    VImage out;

    call( "complexget" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "get", get ) );

    return( out );
}

double VImage::avg( VOption *options )
    throw( VError )
{
    double out;

    call( "avg" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

double VImage::min( VOption *options )
    throw( VError )
{
    double out;

    call( "min" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

double VImage::max( VOption *options )
    throw( VError )
{
    double out;

    call( "max" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

double VImage::deviate( VOption *options )
    throw( VError )
{
    double out;

    call( "deviate" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::stats( VOption *options )
    throw( VError )
{
    VImage out;

    call( "stats" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_find( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_find" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_find_ndim( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_find_ndim" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_find_indexed( VImage index , VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_find_indexed" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "index", index ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hough_line( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hough_line" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hough_circle( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hough_circle" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::project( VImage * rows , VOption *options )
    throw( VError )
{
    VImage columns;

    call( "project" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "columns", &columns ) ->
            set( "rows", rows ) );

    return( columns );
}

VImage VImage::profile( VImage * rows , VOption *options )
    throw( VError )
{
    VImage columns;

    call( "profile" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "columns", &columns ) ->
            set( "rows", rows ) );

    return( columns );
}

VImage VImage::measure( int h , int v , VOption *options )
    throw( VError )
{
    VImage out;

    call( "measure" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "h", h ) ->
            set( "v", v ) );

    return( out );
}

std::vector<double> VImage::getpoint( int x , int y , VOption *options )
    throw( VError )
{
    std::vector<double> out_array;

    call( "getpoint" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out-array", &out_array ) ->
            set( "x", x ) ->
            set( "y", y ) );

    return( out_array );
}

VImage VImage::copy( VOption *options )
    throw( VError )
{
    VImage out;

    call( "copy" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::tilecache( VOption *options )
    throw( VError )
{
    VImage out;

    call( "tilecache" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::linecache( VOption *options )
    throw( VError )
{
    VImage out;

    call( "linecache" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::sequential( VOption *options )
    throw( VError )
{
    VImage out;

    call( "sequential" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::cache( VOption *options )
    throw( VError )
{
    VImage out;

    call( "cache" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::embed( int x , int y , int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "embed" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "x", x ) ->
            set( "y", y ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::flip( VipsDirection direction , VOption *options )
    throw( VError )
{
    VImage out;

    call( "flip" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) ->
            set( "direction", direction ) );

    return( out );
}

VImage VImage::insert( VImage sub , int x , int y , VOption *options )
    throw( VError )
{
    VImage out;

    call( "insert" ,
        (options ? options : VImage::option()) ->
            set( "main", *this ) ->
            set( "sub", sub ) ->
            set( "out", &out ) ->
            set( "x", x ) ->
            set( "y", y ) );

    return( out );
}

VImage VImage::join( VImage in2 , VipsDirection direction , VOption *options )
    throw( VError )
{
    VImage out;

    call( "join" ,
        (options ? options : VImage::option()) ->
            set( "in1", *this ) ->
            set( "in2", in2 ) ->
            set( "out", &out ) ->
            set( "direction", direction ) );

    return( out );
}

VImage VImage::extract_area( int left , int top , int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "extract_area" ,
        (options ? options : VImage::option()) ->
            set( "input", *this ) ->
            set( "out", &out ) ->
            set( "left", left ) ->
            set( "top", top ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::extract_band( int band , VOption *options )
    throw( VError )
{
    VImage out;

    call( "extract_band" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "band", band ) );

    return( out );
}

VImage VImage::bandjoin( std::vector<VImage> in , VOption *options )
    throw( VError )
{
    VImage out;

    call( "bandjoin" ,
        (options ? options : VImage::option()) ->
            set( "in", in ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::bandrank( std::vector<VImage> in , VOption *options )
    throw( VError )
{
    VImage out;

    call( "bandrank" ,
        (options ? options : VImage::option()) ->
            set( "in", in ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::bandmean( VOption *options )
    throw( VError )
{
    VImage out;

    call( "bandmean" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::bandbool( VipsOperationBoolean boolean , VOption *options )
    throw( VError )
{
    VImage out;

    call( "bandbool" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "boolean", boolean ) );

    return( out );
}

VImage VImage::replicate( int across , int down , VOption *options )
    throw( VError )
{
    VImage out;

    call( "replicate" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "across", across ) ->
            set( "down", down ) );

    return( out );
}

VImage VImage::cast( VipsBandFormat format , VOption *options )
    throw( VError )
{
    VImage out;

    call( "cast" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) ->
            set( "format", format ) );

    return( out );
}

VImage VImage::rot( VipsAngle angle , VOption *options )
    throw( VError )
{
    VImage out;

    call( "rot" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) ->
            set( "angle", angle ) );

    return( out );
}

VImage VImage::rot45( VOption *options )
    throw( VError )
{
    VImage out;

    call( "rot45" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::autorot( VOption *options )
    throw( VError )
{
    VImage out;

    call( "autorot" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::ifthenelse( VImage in1 , VImage in2 , VOption *options )
    throw( VError )
{
    VImage out;

    call( "ifthenelse" ,
        (options ? options : VImage::option()) ->
            set( "cond", *this ) ->
            set( "in1", in1 ) ->
            set( "in2", in2 ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::recomb( VImage m , VOption *options )
    throw( VError )
{
    VImage out;

    call( "recomb" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "m", m ) );

    return( out );
}

VImage VImage::flatten( VOption *options )
    throw( VError )
{
    VImage out;

    call( "flatten" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::grid( int tile_height , int across , int down , VOption *options )
    throw( VError )
{
    VImage out;

    call( "grid" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) ->
            set( "tile-height", tile_height ) ->
            set( "across", across ) ->
            set( "down", down ) );

    return( out );
}

VImage VImage::scale( VOption *options )
    throw( VError )
{
    VImage out;

    call( "scale" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::wrap( VOption *options )
    throw( VError )
{
    VImage out;

    call( "wrap" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "in", *this ) );

    return( out );
}

VImage VImage::zoom( int xfac , int yfac , VOption *options )
    throw( VError )
{
    VImage out;

    call( "zoom" ,
        (options ? options : VImage::option()) ->
            set( "input", *this ) ->
            set( "out", &out ) ->
            set( "xfac", xfac ) ->
            set( "yfac", yfac ) );

    return( out );
}

VImage VImage::subsample( int xfac , int yfac , VOption *options )
    throw( VError )
{
    VImage out;

    call( "subsample" ,
        (options ? options : VImage::option()) ->
            set( "input", *this ) ->
            set( "out", &out ) ->
            set( "xfac", xfac ) ->
            set( "yfac", yfac ) );

    return( out );
}

VImage VImage::msb( VOption *options )
    throw( VError )
{
    VImage out;

    call( "msb" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::falsecolour( VOption *options )
    throw( VError )
{
    VImage out;

    call( "falsecolour" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::gamma( VOption *options )
    throw( VError )
{
    VImage out;

    call( "gamma" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::black( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "black" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::gaussnoise( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "gaussnoise" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::text( char * text , VOption *options )
    throw( VError )
{
    VImage out;

    call( "text" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "text", text ) );

    return( out );
}

VImage VImage::xyz( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "xyz" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::gaussmat( double sigma , double min_ampl , VOption *options )
    throw( VError )
{
    VImage out;

    call( "gaussmat" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "sigma", sigma ) ->
            set( "min-ampl", min_ampl ) );

    return( out );
}

VImage VImage::logmat( double sigma , double min_ampl , VOption *options )
    throw( VError )
{
    VImage out;

    call( "logmat" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "sigma", sigma ) ->
            set( "min-ampl", min_ampl ) );

    return( out );
}

VImage VImage::eye( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "eye" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::grey( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "grey" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::zone( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "zone" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::sines( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "sines" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::mask_ideal( int width , int height , double frequency_cutoff , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_ideal" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "frequency-cutoff", frequency_cutoff ) );

    return( out );
}

VImage VImage::mask_ideal_ring( int width , int height , double frequency_cutoff , double ringwidth , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_ideal_ring" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "frequency-cutoff", frequency_cutoff ) ->
            set( "ringwidth", ringwidth ) );

    return( out );
}

VImage VImage::mask_ideal_band( int width , int height , double frequency_cutoff_x , double frequency_cutoff_y , double radius , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_ideal_band" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "frequency-cutoff-x", frequency_cutoff_x ) ->
            set( "frequency-cutoff-y", frequency_cutoff_y ) ->
            set( "radius", radius ) );

    return( out );
}

VImage VImage::mask_butterworth( int width , int height , double order , double frequency_cutoff , double amplitude_cutoff , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_butterworth" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "order", order ) ->
            set( "frequency-cutoff", frequency_cutoff ) ->
            set( "amplitude-cutoff", amplitude_cutoff ) );

    return( out );
}

VImage VImage::mask_butterworth_ring( int width , int height , double order , double frequency_cutoff , double amplitude_cutoff , double ringwidth , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_butterworth_ring" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "order", order ) ->
            set( "frequency-cutoff", frequency_cutoff ) ->
            set( "amplitude-cutoff", amplitude_cutoff ) ->
            set( "ringwidth", ringwidth ) );

    return( out );
}

VImage VImage::mask_butterworth_band( int width , int height , double order , double frequency_cutoff_x , double frequency_cutoff_y , double radius , double amplitude_cutoff , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_butterworth_band" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "order", order ) ->
            set( "frequency-cutoff-x", frequency_cutoff_x ) ->
            set( "frequency-cutoff-y", frequency_cutoff_y ) ->
            set( "radius", radius ) ->
            set( "amplitude-cutoff", amplitude_cutoff ) );

    return( out );
}

VImage VImage::mask_gaussian( int width , int height , double frequency_cutoff , double amplitude_cutoff , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_gaussian" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "frequency-cutoff", frequency_cutoff ) ->
            set( "amplitude-cutoff", amplitude_cutoff ) );

    return( out );
}

VImage VImage::mask_gaussian_ring( int width , int height , double frequency_cutoff , double amplitude_cutoff , double ringwidth , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_gaussian_ring" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "frequency-cutoff", frequency_cutoff ) ->
            set( "amplitude-cutoff", amplitude_cutoff ) ->
            set( "ringwidth", ringwidth ) );

    return( out );
}

VImage VImage::mask_gaussian_band( int width , int height , double frequency_cutoff_x , double frequency_cutoff_y , double radius , double amplitude_cutoff , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_gaussian_band" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "frequency-cutoff-x", frequency_cutoff_x ) ->
            set( "frequency-cutoff-y", frequency_cutoff_y ) ->
            set( "radius", radius ) ->
            set( "amplitude-cutoff", amplitude_cutoff ) );

    return( out );
}

VImage VImage::mask_fractal( int width , int height , double fractal_dimension , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mask_fractal" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "fractal-dimension", fractal_dimension ) );

    return( out );
}

VImage VImage::buildlut( VOption *options )
    throw( VError )
{
    VImage out;

    call( "buildlut" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::invertlut( VOption *options )
    throw( VError )
{
    VImage out;

    call( "invertlut" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::tonelut( VOption *options )
    throw( VError )
{
    VImage out;

    call( "tonelut" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::identity( VOption *options )
    throw( VError )
{
    VImage out;

    call( "identity" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::fractsurf( int width , int height , double fractal_dimension , VOption *options )
    throw( VError )
{
    VImage out;

    call( "fractsurf" ,
        (options ? options : VImage::option()) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "fractal-dimension", fractal_dimension ) );

    return( out );
}

VImage VImage::radload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "radload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::ppmload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "ppmload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::csvload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "csvload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::matrixload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "matrixload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::analyzeload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "analyzeload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::rawload( char * filename , int width , int height , int bands , VOption *options )
    throw( VError )
{
    VImage out;

    call( "rawload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "bands", bands ) );

    return( out );
}

VImage VImage::vipsload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "vipsload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::pngload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "pngload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::pngload_buffer( VipsBlob * buffer , VOption *options )
    throw( VError )
{
    VImage out;

    call( "pngload_buffer" ,
        (options ? options : VImage::option()) ->
            set( "buffer", buffer ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::matload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "matload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::jpegload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "jpegload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::jpegload_buffer( VipsBlob * buffer , VOption *options )
    throw( VError )
{
    VImage out;

    call( "jpegload_buffer" ,
        (options ? options : VImage::option()) ->
            set( "buffer", buffer ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::webpload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "webpload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::webpload_buffer( VipsBlob * buffer , VOption *options )
    throw( VError )
{
    VImage out;

    call( "webpload_buffer" ,
        (options ? options : VImage::option()) ->
            set( "buffer", buffer ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::tiffload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "tiffload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::tiffload_buffer( VipsBlob * buffer , VOption *options )
    throw( VError )
{
    VImage out;

    call( "tiffload_buffer" ,
        (options ? options : VImage::option()) ->
            set( "buffer", buffer ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::openslideload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "openslideload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::magickload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "magickload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::fitsload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "fitsload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::openexrload( char * filename , VOption *options )
    throw( VError )
{
    VImage out;

    call( "openexrload" ,
        (options ? options : VImage::option()) ->
            set( "filename", filename ) ->
            set( "out", &out ) );

    return( out );
}

void VImage::radsave( char * filename , VOption *options )
    throw( VError )
{
    call( "radsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::ppmsave( char * filename , VOption *options )
    throw( VError )
{
    call( "ppmsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::csvsave( char * filename , VOption *options )
    throw( VError )
{
    call( "csvsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::matrixsave( char * filename , VOption *options )
    throw( VError )
{
    call( "matrixsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::matrixprint( VOption *options )
    throw( VError )
{
    call( "matrixprint" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) );
}

void VImage::rawsave( char * filename , VOption *options )
    throw( VError )
{
    call( "rawsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::rawsave_fd( int fd , VOption *options )
    throw( VError )
{
    call( "rawsave_fd" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "fd", fd ) );
}

void VImage::vipssave( char * filename , VOption *options )
    throw( VError )
{
    call( "vipssave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::dzsave( char * filename , VOption *options )
    throw( VError )
{
    call( "dzsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::pngsave( char * filename , VOption *options )
    throw( VError )
{
    call( "pngsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

VipsBlob * VImage::pngsave_buffer( VOption *options )
    throw( VError )
{
    VipsBlob * buffer;

    call( "pngsave_buffer" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "buffer", &buffer ) );

    return( buffer );
}

void VImage::jpegsave( char * filename , VOption *options )
    throw( VError )
{
    call( "jpegsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

VipsBlob * VImage::jpegsave_buffer( VOption *options )
    throw( VError )
{
    VipsBlob * buffer;

    call( "jpegsave_buffer" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "buffer", &buffer ) );

    return( buffer );
}

void VImage::jpegsave_mime( VOption *options )
    throw( VError )
{
    call( "jpegsave_mime" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) );
}

void VImage::webpsave( char * filename , VOption *options )
    throw( VError )
{
    call( "webpsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

VipsBlob * VImage::webpsave_buffer( VOption *options )
    throw( VError )
{
    VipsBlob * buffer;

    call( "webpsave_buffer" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "buffer", &buffer ) );

    return( buffer );
}

void VImage::tiffsave( char * filename , VOption *options )
    throw( VError )
{
    call( "tiffsave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

void VImage::fitssave( char * filename , VOption *options )
    throw( VError )
{
    call( "fitssave" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "filename", filename ) );
}

VImage VImage::shrink( double xshrink , double yshrink , VOption *options )
    throw( VError )
{
    VImage out;

    call( "shrink" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "xshrink", xshrink ) ->
            set( "yshrink", yshrink ) );

    return( out );
}

VImage VImage::quadratic( VImage coeff , VOption *options )
    throw( VError )
{
    VImage out;

    call( "quadratic" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "coeff", coeff ) );

    return( out );
}

VImage VImage::affine( std::vector<double> matrix , VOption *options )
    throw( VError )
{
    VImage out;

    call( "affine" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "matrix", matrix ) );

    return( out );
}

VImage VImage::similarity( VOption *options )
    throw( VError )
{
    VImage out;

    call( "similarity" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::resize( double scale , VOption *options )
    throw( VError )
{
    VImage out;

    call( "resize" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "scale", scale ) );

    return( out );
}

VImage VImage::colourspace( VipsInterpretation space , VOption *options )
    throw( VError )
{
    VImage out;

    call( "colourspace" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "space", space ) );

    return( out );
}

VImage VImage::Lab2XYZ( VOption *options )
    throw( VError )
{
    VImage out;

    call( "Lab2XYZ" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::XYZ2Lab( VOption *options )
    throw( VError )
{
    VImage out;

    call( "XYZ2Lab" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::Lab2LCh( VOption *options )
    throw( VError )
{
    VImage out;

    call( "Lab2LCh" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LCh2Lab( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LCh2Lab" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LCh2CMC( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LCh2CMC" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::CMC2LCh( VOption *options )
    throw( VError )
{
    VImage out;

    call( "CMC2LCh" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::XYZ2Yxy( VOption *options )
    throw( VError )
{
    VImage out;

    call( "XYZ2Yxy" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::Yxy2XYZ( VOption *options )
    throw( VError )
{
    VImage out;

    call( "Yxy2XYZ" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::scRGB2XYZ( VOption *options )
    throw( VError )
{
    VImage out;

    call( "scRGB2XYZ" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::XYZ2scRGB( VOption *options )
    throw( VError )
{
    VImage out;

    call( "XYZ2scRGB" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LabQ2Lab( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LabQ2Lab" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::Lab2LabQ( VOption *options )
    throw( VError )
{
    VImage out;

    call( "Lab2LabQ" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LabQ2LabS( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LabQ2LabS" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LabS2LabQ( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LabS2LabQ" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LabS2Lab( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LabS2Lab" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::Lab2LabS( VOption *options )
    throw( VError )
{
    VImage out;

    call( "Lab2LabS" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::rad2float( VOption *options )
    throw( VError )
{
    VImage out;

    call( "rad2float" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::float2rad( VOption *options )
    throw( VError )
{
    VImage out;

    call( "float2rad" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::LabQ2sRGB( VOption *options )
    throw( VError )
{
    VImage out;

    call( "LabQ2sRGB" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::sRGB2scRGB( VOption *options )
    throw( VError )
{
    VImage out;

    call( "sRGB2scRGB" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::scRGB2sRGB( VOption *options )
    throw( VError )
{
    VImage out;

    call( "scRGB2sRGB" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::icc_import( VOption *options )
    throw( VError )
{
    VImage out;

    call( "icc_import" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::icc_export( VOption *options )
    throw( VError )
{
    VImage out;

    call( "icc_export" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::icc_transform( char * output_profile , VOption *options )
    throw( VError )
{
    VImage out;

    call( "icc_transform" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "output-profile", output_profile ) );

    return( out );
}

VImage VImage::dE76( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "dE76" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::dE00( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "dE00" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::dECMC( VImage right , VOption *options )
    throw( VError )
{
    VImage out;

    call( "dECMC" ,
        (options ? options : VImage::option()) ->
            set( "left", *this ) ->
            set( "right", right ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::maplut( VImage lut , VOption *options )
    throw( VError )
{
    VImage out;

    call( "maplut" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "lut", lut ) );

    return( out );
}

int VImage::percent( double percent , VOption *options )
    throw( VError )
{
    int threshold;

    call( "percent" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "percent", percent ) ->
            set( "threshold", &threshold ) );

    return( threshold );
}

VImage VImage::stdif( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "stdif" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

VImage VImage::hist_cum( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_cum" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_match( VImage ref , VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_match" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "ref", ref ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_norm( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_norm" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_equal( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_equal" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_plot( VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_plot" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::hist_local( int width , int height , VOption *options )
    throw( VError )
{
    VImage out;

    call( "hist_local" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) );

    return( out );
}

bool VImage::hist_ismonotonic( VOption *options )
    throw( VError )
{
    bool monotonic;

    call( "hist_ismonotonic" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "monotonic", &monotonic ) );

    return( monotonic );
}

VImage VImage::conv( VImage mask , VOption *options )
    throw( VError )
{
    VImage out;

    call( "conv" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "mask", mask ) );

    return( out );
}

VImage VImage::compass( VImage mask , VOption *options )
    throw( VError )
{
    VImage out;

    call( "compass" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "mask", mask ) );

    return( out );
}

VImage VImage::convsep( VImage mask , VOption *options )
    throw( VError )
{
    VImage out;

    call( "convsep" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "mask", mask ) );

    return( out );
}

VImage VImage::fastcor( VImage ref , VOption *options )
    throw( VError )
{
    VImage out;

    call( "fastcor" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "ref", ref ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::spcor( VImage ref , VOption *options )
    throw( VError )
{
    VImage out;

    call( "spcor" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "ref", ref ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::sharpen( VOption *options )
    throw( VError )
{
    VImage out;

    call( "sharpen" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::gaussblur( double sigma , VOption *options )
    throw( VError )
{
    VImage out;

    call( "gaussblur" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "sigma", sigma ) );

    return( out );
}

VImage VImage::fwfft( VOption *options )
    throw( VError )
{
    VImage out;

    call( "fwfft" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::invfft( VOption *options )
    throw( VError )
{
    VImage out;

    call( "invfft" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::freqmult( VImage mask , VOption *options )
    throw( VError )
{
    VImage out;

    call( "freqmult" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "mask", mask ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::spectrum( VOption *options )
    throw( VError )
{
    VImage out;

    call( "spectrum" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::phasecor( VImage in2 , VOption *options )
    throw( VError )
{
    VImage out;

    call( "phasecor" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "in2", in2 ) ->
            set( "out", &out ) );

    return( out );
}

VImage VImage::morph( VImage mask , VipsOperationMorphology morph , VOption *options )
    throw( VError )
{
    VImage out;

    call( "morph" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "mask", mask ) ->
            set( "morph", morph ) );

    return( out );
}

VImage VImage::rank( int width , int height , int index , VOption *options )
    throw( VError )
{
    VImage out;

    call( "rank" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) ->
            set( "width", width ) ->
            set( "height", height ) ->
            set( "index", index ) );

    return( out );
}

double VImage::countlines( VipsDirection direction , VOption *options )
    throw( VError )
{
    double nolines;

    call( "countlines" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "nolines", &nolines ) ->
            set( "direction", direction ) );

    return( nolines );
}

VImage VImage::labelregions( VOption *options )
    throw( VError )
{
    VImage mask;

    call( "labelregions" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "mask", &mask ) );

    return( mask );
}

void VImage::draw_rect( std::vector<double> ink , int left , int top , int width , int height , VOption *options )
    throw( VError )
{
    call( "draw_rect" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "ink", ink ) ->
            set( "left", left ) ->
            set( "top", top ) ->
            set( "width", width ) ->
            set( "height", height ) );
}

void VImage::draw_mask( std::vector<double> ink , VImage mask , int x , int y , VOption *options )
    throw( VError )
{
    call( "draw_mask" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "ink", ink ) ->
            set( "mask", mask ) ->
            set( "x", x ) ->
            set( "y", y ) );
}

void VImage::draw_line( std::vector<double> ink , int x1 , int y1 , int x2 , int y2 , VOption *options )
    throw( VError )
{
    call( "draw_line" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "ink", ink ) ->
            set( "x1", x1 ) ->
            set( "y1", y1 ) ->
            set( "x2", x2 ) ->
            set( "y2", y2 ) );
}

void VImage::draw_circle( std::vector<double> ink , int cx , int cy , int radius , VOption *options )
    throw( VError )
{
    call( "draw_circle" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "ink", ink ) ->
            set( "cx", cx ) ->
            set( "cy", cy ) ->
            set( "radius", radius ) );
}

void VImage::draw_flood( std::vector<double> ink , int x , int y , VOption *options )
    throw( VError )
{
    call( "draw_flood" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "ink", ink ) ->
            set( "x", x ) ->
            set( "y", y ) );
}

void VImage::draw_image( VImage sub , int x , int y , VOption *options )
    throw( VError )
{
    call( "draw_image" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "sub", sub ) ->
            set( "x", x ) ->
            set( "y", y ) );
}

void VImage::draw_smudge( int left , int top , int width , int height , VOption *options )
    throw( VError )
{
    call( "draw_smudge" ,
        (options ? options : VImage::option()) ->
            set( "image", *this ) ->
            set( "left", left ) ->
            set( "top", top ) ->
            set( "width", width ) ->
            set( "height", height ) );
}

VImage VImage::merge( VImage sec , VipsDirection direction , int dx , int dy , VOption *options )
    throw( VError )
{
    VImage out;

    call( "merge" ,
        (options ? options : VImage::option()) ->
            set( "ref", *this ) ->
            set( "sec", sec ) ->
            set( "out", &out ) ->
            set( "direction", direction ) ->
            set( "dx", dx ) ->
            set( "dy", dy ) );

    return( out );
}

VImage VImage::mosaic( VImage sec , VipsDirection direction , int xref , int yref , int xsec , int ysec , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mosaic" ,
        (options ? options : VImage::option()) ->
            set( "ref", *this ) ->
            set( "sec", sec ) ->
            set( "out", &out ) ->
            set( "direction", direction ) ->
            set( "xref", xref ) ->
            set( "yref", yref ) ->
            set( "xsec", xsec ) ->
            set( "ysec", ysec ) );

    return( out );
}

VImage VImage::mosaic1( VImage sec , VipsDirection direction , int xr1 , int yr1 , int xs1 , int ys1 , int xr2 , int yr2 , int xs2 , int ys2 , VOption *options )
    throw( VError )
{
    VImage out;

    call( "mosaic1" ,
        (options ? options : VImage::option()) ->
            set( "ref", *this ) ->
            set( "sec", sec ) ->
            set( "out", &out ) ->
            set( "direction", direction ) ->
            set( "xr1", xr1 ) ->
            set( "yr1", yr1 ) ->
            set( "xs1", xs1 ) ->
            set( "ys1", ys1 ) ->
            set( "xr2", xr2 ) ->
            set( "yr2", yr2 ) ->
            set( "xs2", xs2 ) ->
            set( "ys2", ys2 ) );

    return( out );
}

VImage VImage::match( VImage sec , int xr1 , int yr1 , int xs1 , int ys1 , int xr2 , int yr2 , int xs2 , int ys2 , VOption *options )
    throw( VError )
{
    VImage out;

    call( "match" ,
        (options ? options : VImage::option()) ->
            set( "ref", *this ) ->
            set( "sec", sec ) ->
            set( "out", &out ) ->
            set( "xr1", xr1 ) ->
            set( "yr1", yr1 ) ->
            set( "xs1", xs1 ) ->
            set( "ys1", ys1 ) ->
            set( "xr2", xr2 ) ->
            set( "yr2", yr2 ) ->
            set( "xs2", xs2 ) ->
            set( "ys2", ys2 ) );

    return( out );
}

VImage VImage::globalbalance( VOption *options )
    throw( VError )
{
    VImage out;

    call( "globalbalance" ,
        (options ? options : VImage::option()) ->
            set( "in", *this ) ->
            set( "out", &out ) );

    return( out );
}

