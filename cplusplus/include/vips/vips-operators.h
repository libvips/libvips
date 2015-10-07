// headers for vips operations
// Tue Oct  6 16:54:32 BST 2015
// this file is generated automatically, do not edit!

static void system( char * cmd_format , VOption *options = 0 )
    throw( VError );
VImage add( VImage right , VOption *options = 0 )
    throw( VError );
VImage subtract( VImage right , VOption *options = 0 )
    throw( VError );
VImage multiply( VImage right , VOption *options = 0 )
    throw( VError );
VImage divide( VImage right , VOption *options = 0 )
    throw( VError );
VImage relational( VImage right , VipsOperationRelational relational , VOption *options = 0 )
    throw( VError );
VImage remainder( VImage right , VOption *options = 0 )
    throw( VError );
VImage boolean( VImage right , VipsOperationBoolean boolean , VOption *options = 0 )
    throw( VError );
VImage math2( VImage right , VipsOperationMath2 math2 , VOption *options = 0 )
    throw( VError );
VImage complex2( VImage right , VipsOperationComplex2 cmplx , VOption *options = 0 )
    throw( VError );
VImage complexform( VImage right , VOption *options = 0 )
    throw( VError );
static VImage sum( std::vector<VImage> in , VOption *options = 0 )
    throw( VError );
VImage invert( VOption *options = 0 )
    throw( VError );
VImage linear( std::vector<double> a , std::vector<double> b , VOption *options = 0 )
    throw( VError );
VImage math( VipsOperationMath math , VOption *options = 0 )
    throw( VError );
VImage abs( VOption *options = 0 )
    throw( VError );
VImage sign( VOption *options = 0 )
    throw( VError );
VImage round( VipsOperationRound round , VOption *options = 0 )
    throw( VError );
VImage relational_const( std::vector<double> c , VipsOperationRelational relational , VOption *options = 0 )
    throw( VError );
VImage remainder_const( std::vector<double> c , VOption *options = 0 )
    throw( VError );
VImage boolean_const( std::vector<double> c , VipsOperationBoolean boolean , VOption *options = 0 )
    throw( VError );
VImage math2_const( std::vector<double> c , VipsOperationMath2 math2 , VOption *options = 0 )
    throw( VError );
VImage complex( VipsOperationComplex cmplx , VOption *options = 0 )
    throw( VError );
VImage complexget( VipsOperationComplexget get , VOption *options = 0 )
    throw( VError );
double avg( VOption *options = 0 )
    throw( VError );
double min( VOption *options = 0 )
    throw( VError );
double max( VOption *options = 0 )
    throw( VError );
double deviate( VOption *options = 0 )
    throw( VError );
VImage stats( VOption *options = 0 )
    throw( VError );
VImage hist_find( VOption *options = 0 )
    throw( VError );
VImage hist_find_ndim( VOption *options = 0 )
    throw( VError );
VImage hist_find_indexed( VImage index , VOption *options = 0 )
    throw( VError );
VImage hough_line( VOption *options = 0 )
    throw( VError );
VImage hough_circle( VOption *options = 0 )
    throw( VError );
VImage project( VImage * rows , VOption *options = 0 )
    throw( VError );
VImage profile( VImage * rows , VOption *options = 0 )
    throw( VError );
VImage measure( int h , int v , VOption *options = 0 )
    throw( VError );
std::vector<double> getpoint( int x , int y , VOption *options = 0 )
    throw( VError );
VImage copy( VOption *options = 0 )
    throw( VError );
VImage tilecache( VOption *options = 0 )
    throw( VError );
VImage linecache( VOption *options = 0 )
    throw( VError );
VImage sequential( VOption *options = 0 )
    throw( VError );
VImage cache( VOption *options = 0 )
    throw( VError );
VImage embed( int x , int y , int width , int height , VOption *options = 0 )
    throw( VError );
VImage flip( VipsDirection direction , VOption *options = 0 )
    throw( VError );
VImage insert( VImage sub , int x , int y , VOption *options = 0 )
    throw( VError );
VImage join( VImage in2 , VipsDirection direction , VOption *options = 0 )
    throw( VError );
VImage extract_area( int left , int top , int width , int height , VOption *options = 0 )
    throw( VError );
VImage extract_band( int band , VOption *options = 0 )
    throw( VError );
static VImage bandjoin( std::vector<VImage> in , VOption *options = 0 )
    throw( VError );
static VImage bandrank( std::vector<VImage> in , VOption *options = 0 )
    throw( VError );
VImage bandmean( VOption *options = 0 )
    throw( VError );
VImage bandbool( VipsOperationBoolean boolean , VOption *options = 0 )
    throw( VError );
VImage replicate( int across , int down , VOption *options = 0 )
    throw( VError );
VImage cast( VipsBandFormat format , VOption *options = 0 )
    throw( VError );
VImage rot( VipsAngle angle , VOption *options = 0 )
    throw( VError );
VImage rot45( VOption *options = 0 )
    throw( VError );
VImage autorot( VOption *options = 0 )
    throw( VError );
VImage ifthenelse( VImage in1 , VImage in2 , VOption *options = 0 )
    throw( VError );
VImage recomb( VImage m , VOption *options = 0 )
    throw( VError );
VImage bandfold( VOption *options = 0 )
    throw( VError );
VImage bandunfold( VOption *options = 0 )
    throw( VError );
VImage flatten( VOption *options = 0 )
    throw( VError );
VImage premultiply( VOption *options = 0 )
    throw( VError );
VImage unpremultiply( VOption *options = 0 )
    throw( VError );
VImage grid( int tile_height , int across , int down , VOption *options = 0 )
    throw( VError );
VImage scale( VOption *options = 0 )
    throw( VError );
VImage wrap( VOption *options = 0 )
    throw( VError );
VImage zoom( int xfac , int yfac , VOption *options = 0 )
    throw( VError );
VImage subsample( int xfac , int yfac , VOption *options = 0 )
    throw( VError );
VImage msb( VOption *options = 0 )
    throw( VError );
VImage byteswap( VOption *options = 0 )
    throw( VError );
VImage falsecolour( VOption *options = 0 )
    throw( VError );
VImage gamma( VOption *options = 0 )
    throw( VError );
static VImage black( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage gaussnoise( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage text( char * text , VOption *options = 0 )
    throw( VError );
static VImage xyz( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage gaussmat( double sigma , double min_ampl , VOption *options = 0 )
    throw( VError );
static VImage logmat( double sigma , double min_ampl , VOption *options = 0 )
    throw( VError );
static VImage eye( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage grey( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage zone( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage sines( int width , int height , VOption *options = 0 )
    throw( VError );
static VImage mask_ideal( int width , int height , double frequency_cutoff , VOption *options = 0 )
    throw( VError );
static VImage mask_ideal_ring( int width , int height , double frequency_cutoff , double ringwidth , VOption *options = 0 )
    throw( VError );
static VImage mask_ideal_band( int width , int height , double frequency_cutoff_x , double frequency_cutoff_y , double radius , VOption *options = 0 )
    throw( VError );
static VImage mask_butterworth( int width , int height , double order , double frequency_cutoff , double amplitude_cutoff , VOption *options = 0 )
    throw( VError );
static VImage mask_butterworth_ring( int width , int height , double order , double frequency_cutoff , double amplitude_cutoff , double ringwidth , VOption *options = 0 )
    throw( VError );
static VImage mask_butterworth_band( int width , int height , double order , double frequency_cutoff_x , double frequency_cutoff_y , double radius , double amplitude_cutoff , VOption *options = 0 )
    throw( VError );
static VImage mask_gaussian( int width , int height , double frequency_cutoff , double amplitude_cutoff , VOption *options = 0 )
    throw( VError );
static VImage mask_gaussian_ring( int width , int height , double frequency_cutoff , double amplitude_cutoff , double ringwidth , VOption *options = 0 )
    throw( VError );
static VImage mask_gaussian_band( int width , int height , double frequency_cutoff_x , double frequency_cutoff_y , double radius , double amplitude_cutoff , VOption *options = 0 )
    throw( VError );
static VImage mask_fractal( int width , int height , double fractal_dimension , VOption *options = 0 )
    throw( VError );
VImage buildlut( VOption *options = 0 )
    throw( VError );
VImage invertlut( VOption *options = 0 )
    throw( VError );
static VImage tonelut( VOption *options = 0 )
    throw( VError );
static VImage identity( VOption *options = 0 )
    throw( VError );
static VImage fractsurf( int width , int height , double fractal_dimension , VOption *options = 0 )
    throw( VError );
static VImage radload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage ppmload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage csvload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage matrixload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage analyzeload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage rawload( char * filename , int width , int height , int bands , VOption *options = 0 )
    throw( VError );
static VImage vipsload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage pngload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage pngload_buffer( VipsBlob * buffer , VOption *options = 0 )
    throw( VError );
static VImage matload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage jpegload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage jpegload_buffer( VipsBlob * buffer , VOption *options = 0 )
    throw( VError );
static VImage webpload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage webpload_buffer( VipsBlob * buffer , VOption *options = 0 )
    throw( VError );
static VImage tiffload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage tiffload_buffer( VipsBlob * buffer , VOption *options = 0 )
    throw( VError );
static VImage openslideload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage magickload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage magickload_buffer( VipsBlob * buffer , VOption *options = 0 )
    throw( VError );
static VImage fitsload( char * filename , VOption *options = 0 )
    throw( VError );
static VImage openexrload( char * filename , VOption *options = 0 )
    throw( VError );
void radsave( char * filename , VOption *options = 0 )
    throw( VError );
void ppmsave( char * filename , VOption *options = 0 )
    throw( VError );
void csvsave( char * filename , VOption *options = 0 )
    throw( VError );
void matrixsave( char * filename , VOption *options = 0 )
    throw( VError );
void matrixprint( VOption *options = 0 )
    throw( VError );
void rawsave( char * filename , VOption *options = 0 )
    throw( VError );
void rawsave_fd( int fd , VOption *options = 0 )
    throw( VError );
void vipssave( char * filename , VOption *options = 0 )
    throw( VError );
void dzsave( char * filename , VOption *options = 0 )
    throw( VError );
void pngsave( char * filename , VOption *options = 0 )
    throw( VError );
VipsBlob * pngsave_buffer( VOption *options = 0 )
    throw( VError );
void jpegsave( char * filename , VOption *options = 0 )
    throw( VError );
VipsBlob * jpegsave_buffer( VOption *options = 0 )
    throw( VError );
void jpegsave_mime( VOption *options = 0 )
    throw( VError );
void webpsave( char * filename , VOption *options = 0 )
    throw( VError );
VipsBlob * webpsave_buffer( VOption *options = 0 )
    throw( VError );
void tiffsave( char * filename , VOption *options = 0 )
    throw( VError );
void fitssave( char * filename , VOption *options = 0 )
    throw( VError );
VImage shrink( double xshrink , double yshrink , VOption *options = 0 )
    throw( VError );
VImage quadratic( VImage coeff , VOption *options = 0 )
    throw( VError );
VImage affine( std::vector<double> matrix , VOption *options = 0 )
    throw( VError );
VImage similarity( VOption *options = 0 )
    throw( VError );
VImage resize( double scale , VOption *options = 0 )
    throw( VError );
VImage colourspace( VipsInterpretation space , VOption *options = 0 )
    throw( VError );
VImage Lab2XYZ( VOption *options = 0 )
    throw( VError );
VImage XYZ2Lab( VOption *options = 0 )
    throw( VError );
VImage Lab2LCh( VOption *options = 0 )
    throw( VError );
VImage LCh2Lab( VOption *options = 0 )
    throw( VError );
VImage LCh2CMC( VOption *options = 0 )
    throw( VError );
VImage CMC2LCh( VOption *options = 0 )
    throw( VError );
VImage XYZ2Yxy( VOption *options = 0 )
    throw( VError );
VImage Yxy2XYZ( VOption *options = 0 )
    throw( VError );
VImage scRGB2XYZ( VOption *options = 0 )
    throw( VError );
VImage XYZ2scRGB( VOption *options = 0 )
    throw( VError );
VImage LabQ2Lab( VOption *options = 0 )
    throw( VError );
VImage Lab2LabQ( VOption *options = 0 )
    throw( VError );
VImage LabQ2LabS( VOption *options = 0 )
    throw( VError );
VImage LabS2LabQ( VOption *options = 0 )
    throw( VError );
VImage LabS2Lab( VOption *options = 0 )
    throw( VError );
VImage Lab2LabS( VOption *options = 0 )
    throw( VError );
VImage rad2float( VOption *options = 0 )
    throw( VError );
VImage float2rad( VOption *options = 0 )
    throw( VError );
VImage LabQ2sRGB( VOption *options = 0 )
    throw( VError );
VImage sRGB2HSV( VOption *options = 0 )
    throw( VError );
VImage HSV2sRGB( VOption *options = 0 )
    throw( VError );
VImage icc_import( VOption *options = 0 )
    throw( VError );
VImage icc_export( VOption *options = 0 )
    throw( VError );
VImage icc_transform( char * output_profile , VOption *options = 0 )
    throw( VError );
VImage dE76( VImage right , VOption *options = 0 )
    throw( VError );
VImage dE00( VImage right , VOption *options = 0 )
    throw( VError );
VImage dECMC( VImage right , VOption *options = 0 )
    throw( VError );
VImage sRGB2scRGB( VOption *options = 0 )
    throw( VError );
VImage scRGB2BW( VOption *options = 0 )
    throw( VError );
VImage scRGB2sRGB( VOption *options = 0 )
    throw( VError );
VImage maplut( VImage lut , VOption *options = 0 )
    throw( VError );
int percent( double percent , VOption *options = 0 )
    throw( VError );
VImage stdif( int width , int height , VOption *options = 0 )
    throw( VError );
VImage hist_cum( VOption *options = 0 )
    throw( VError );
VImage hist_match( VImage ref , VOption *options = 0 )
    throw( VError );
VImage hist_norm( VOption *options = 0 )
    throw( VError );
VImage hist_equal( VOption *options = 0 )
    throw( VError );
VImage hist_plot( VOption *options = 0 )
    throw( VError );
VImage hist_local( int width , int height , VOption *options = 0 )
    throw( VError );
bool hist_ismonotonic( VOption *options = 0 )
    throw( VError );
double hist_entropy( VOption *options = 0 )
    throw( VError );
VImage conv( VImage mask , VOption *options = 0 )
    throw( VError );
VImage compass( VImage mask , VOption *options = 0 )
    throw( VError );
VImage convsep( VImage mask , VOption *options = 0 )
    throw( VError );
VImage fastcor( VImage ref , VOption *options = 0 )
    throw( VError );
VImage spcor( VImage ref , VOption *options = 0 )
    throw( VError );
VImage sharpen( VOption *options = 0 )
    throw( VError );
VImage gaussblur( double sigma , VOption *options = 0 )
    throw( VError );
VImage fwfft( VOption *options = 0 )
    throw( VError );
VImage invfft( VOption *options = 0 )
    throw( VError );
VImage freqmult( VImage mask , VOption *options = 0 )
    throw( VError );
VImage spectrum( VOption *options = 0 )
    throw( VError );
VImage phasecor( VImage in2 , VOption *options = 0 )
    throw( VError );
VImage morph( VImage mask , VipsOperationMorphology morph , VOption *options = 0 )
    throw( VError );
VImage rank( int width , int height , int index , VOption *options = 0 )
    throw( VError );
double countlines( VipsDirection direction , VOption *options = 0 )
    throw( VError );
VImage labelregions( VOption *options = 0 )
    throw( VError );
void draw_rect( std::vector<double> ink , int left , int top , int width , int height , VOption *options = 0 )
    throw( VError );
void draw_mask( std::vector<double> ink , VImage mask , int x , int y , VOption *options = 0 )
    throw( VError );
void draw_line( std::vector<double> ink , int x1 , int y1 , int x2 , int y2 , VOption *options = 0 )
    throw( VError );
void draw_circle( std::vector<double> ink , int cx , int cy , int radius , VOption *options = 0 )
    throw( VError );
void draw_flood( std::vector<double> ink , int x , int y , VOption *options = 0 )
    throw( VError );
void draw_image( VImage sub , int x , int y , VOption *options = 0 )
    throw( VError );
void draw_smudge( int left , int top , int width , int height , VOption *options = 0 )
    throw( VError );
VImage merge( VImage sec , VipsDirection direction , int dx , int dy , VOption *options = 0 )
    throw( VError );
VImage mosaic( VImage sec , VipsDirection direction , int xref , int yref , int xsec , int ysec , VOption *options = 0 )
    throw( VError );
VImage mosaic1( VImage sec , VipsDirection direction , int xr1 , int yr1 , int xs1 , int ys1 , int xr2 , int yr2 , int xs2 , int ys2 , VOption *options = 0 )
    throw( VError );
VImage match( VImage sec , int xr1 , int yr1 , int xs1 , int ys1 , int xr2 , int yr2 , int xs2 , int ys2 , VOption *options = 0 )
    throw( VError );
VImage globalbalance( VOption *options = 0 )
    throw( VError );
