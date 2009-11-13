
// bodies for package arithmetic
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_abs: absolute value
VImage VImage::abs() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_abs" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_acostra: acos of image (result in degrees)
VImage VImage::acos() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_acostra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_add: add two images
VImage VImage::add( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_add" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_asintra: asin of image (result in degrees)
VImage VImage::asin() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_asintra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_atantra: atan of image (result in degrees)
VImage VImage::atan() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_atantra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_avg: average value of image
double VImage::avg() throw( VError )
{
	VImage in = *this;
	double value;

	Vargv _vec( "im_avg" );

	_vec.data(0) = in.image();
	_vec.call();
	value = *((double*)_vec.data(1));

	return( value );
}

// im_point_bilinear: interpolate value at single point, linearly
double VImage::point_bilinear( double x, double y, int band ) throw( VError )
{
	VImage in = *this;
	double val;

	Vargv _vec( "im_point_bilinear" );

	_vec.data(0) = in.image();
	*((double*) _vec.data(1)) = x;
	*((double*) _vec.data(2)) = y;
	*((int*) _vec.data(3)) = band;
	_vec.call();
	val = *((double*)_vec.data(4));

	return( val );
}

// im_bandmean: average image bands
VImage VImage::bandmean() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_bandmean" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_ceil: round to smallest integal value not less than
VImage VImage::ceil() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_ceil" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_costra: cos of image (angles in degrees)
VImage VImage::cos() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_costra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_cross_phase: phase of cross power spectrum of two complex images
VImage VImage::cross_phase( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_cross_phase" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_deviate: standard deviation of image
double VImage::deviate() throw( VError )
{
	VImage in = *this;
	double value;

	Vargv _vec( "im_deviate" );

	_vec.data(0) = in.image();
	_vec.call();
	value = *((double*)_vec.data(1));

	return( value );
}

// im_divide: divide two images
VImage VImage::divide( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_divide" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_exp10tra: 10^pel of image
VImage VImage::exp10() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_exp10tra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_expntra: x^pel of image
VImage VImage::expn( double x ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_expntra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = x;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_expntra_vec: [x,y,z]^pel of image
VImage VImage::expn( std::vector<double> v ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_expntra_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = v.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[v.size()];
	for( unsigned int i = 0; i < v.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = v[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_exptra: e^pel of image
VImage VImage::exp() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_exptra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_floor: round to largest integal value not greater than
VImage VImage::floor() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_floor" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_invert: photographic negative
VImage VImage::invert() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_invert" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lintra: calculate a*in + b = outfile
VImage VImage::lin( double a, double b ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lintra" );

	*((double*) _vec.data(0)) = a;
	_vec.data(1) = in.image();
	*((double*) _vec.data(2)) = b;
	_vec.data(3) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_linreg: pixelwise linear regression
VImage VImage::linreg( std::vector<VImage> ins, std::vector<double> xs ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_linreg" );

	((im_imagevec_object*) _vec.data(0))->n = ins.size();
	((im_imagevec_object*) _vec.data(0))->vec = new IMAGE *[ins.size()];
	for( unsigned int i = 0; i < ins.size(); i++ )
		((im_imagevec_object*) _vec.data(0))->vec[i] = ins[i].image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = xs.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[xs.size()];
	for( unsigned int i = 0; i < xs.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = xs[i];
	_vec.call();
	for( unsigned int i = 0; i < ins.size(); i++ )
		out._ref->addref( ins[i]._ref );

	return( out );
}

// im_lintra_vec: calculate a*in + b -> out, a and b vectors
VImage VImage::lin( std::vector<double> a, std::vector<double> b ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lintra_vec" );

	((im_doublevec_object*) _vec.data(0))->n = a.size();
	((im_doublevec_object*) _vec.data(0))->vec = new double[a.size()];
	for( unsigned int i = 0; i < a.size(); i++ )
		((im_doublevec_object*) _vec.data(0))->vec[i] = a[i];
	_vec.data(1) = in.image();
	((im_doublevec_object*) _vec.data(2))->n = b.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[b.size()];
	for( unsigned int i = 0; i < b.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = b[i];
	_vec.data(3) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_log10tra: log10 of image
VImage VImage::log10() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_log10tra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_logtra: ln of image
VImage VImage::log() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_logtra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_max: maximum value of image
double VImage::max() throw( VError )
{
	VImage in = *this;
	double value;

	Vargv _vec( "im_max" );

	_vec.data(0) = in.image();
	_vec.call();
	value = *((double*)_vec.data(1));

	return( value );
}

// im_maxpos: position of maximum value of image
std::complex<double> VImage::maxpos() throw( VError )
{
	VImage in = *this;
	std::complex<double> position;

	Vargv _vec( "im_maxpos" );

	_vec.data(0) = in.image();
	_vec.call();
	position = *((std::complex<double>*)_vec.data(1));

	return( position );
}

// im_maxpos_avg: position of maximum value of image, averaging in case of draw
double VImage::maxpos_avg( double& y, double& out ) throw( VError )
{
	VImage in = *this;
	double x;

	Vargv _vec( "im_maxpos_avg" );

	_vec.data(0) = in.image();
	_vec.call();
	x = *((double*)_vec.data(1));
	y = *((double*)_vec.data(2));
	out = *((double*)_vec.data(3));

	return( x );
}

// im_measure: measure averages of a grid of patches
VDMask VImage::measure( int x, int y, int w, int h, int h_patches, int v_patches ) throw( VError )
{
	VImage in = *this;
	VDMask mask;

	Vargv _vec( "im_measure" );

	_vec.data(0) = in.image();
	((im_mask_object*) _vec.data(1))->name = (char*)"noname";
	*((int*) _vec.data(2)) = x;
	*((int*) _vec.data(3)) = y;
	*((int*) _vec.data(4)) = w;
	*((int*) _vec.data(5)) = h;
	*((int*) _vec.data(6)) = h_patches;
	*((int*) _vec.data(7)) = v_patches;
	_vec.call();
	mask.embed( (DOUBLEMASK *)((im_mask_object*)_vec.data(1))->mask );

	return( mask );
}

// im_min: minimum value of image
double VImage::min() throw( VError )
{
	VImage in = *this;
	double value;

	Vargv _vec( "im_min" );

	_vec.data(0) = in.image();
	_vec.call();
	value = *((double*)_vec.data(1));

	return( value );
}

// im_minpos: position of minimum value of image
std::complex<double> VImage::minpos() throw( VError )
{
	VImage in = *this;
	std::complex<double> position;

	Vargv _vec( "im_minpos" );

	_vec.data(0) = in.image();
	_vec.call();
	position = *((std::complex<double>*)_vec.data(1));

	return( position );
}

// im_multiply: multiply two images
VImage VImage::multiply( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_multiply" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_powtra: pel^x of image
VImage VImage::pow( double x ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_powtra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = x;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_powtra_vec: pel^[x,y,z] of image
VImage VImage::pow( std::vector<double> v ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_powtra_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = v.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[v.size()];
	for( unsigned int i = 0; i < v.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = v[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_recomb: linear recombination with mask
VImage VImage::recomb( VDMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_recomb" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().dptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_remainder: remainder after integer division
VImage VImage::remainder( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_remainder" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_remainderconst: remainder after integer division by a constant
VImage VImage::remainder( double x ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_remainderconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = x;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_remainder_vec: remainder after integer division by a vector of constants
VImage VImage::remainder( std::vector<double> x ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_remainder_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = x.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[x.size()];
	for( unsigned int i = 0; i < x.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = x[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_rint: round to nearest integal value
VImage VImage::rint() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rint" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_sign: unit vector in direction of value
VImage VImage::sign() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_sign" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_sintra: sin of image (angles in degrees)
VImage VImage::sin() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_sintra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_stats: many image statistics in one pass
VDMask VImage::stats() throw( VError )
{
	VImage in = *this;
	VDMask statistics;

	Vargv _vec( "im_stats" );

	_vec.data(0) = in.image();
	((im_mask_object*) _vec.data(1))->name = (char*)"noname";
	_vec.call();
	statistics.embed( (DOUBLEMASK *)((im_mask_object*)_vec.data(1))->mask );

	return( statistics );
}

// im_subtract: subtract two images
VImage VImage::subtract( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_subtract" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_tantra: tan of image (angles in degrees)
VImage VImage::tan() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_tantra" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}


// bodies for package boolean
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_andimage: bitwise and of two images
VImage VImage::andimage( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_andimage" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_andimageconst: bitwise and of an image with a constant
VImage VImage::andimage( int c ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_andimageconst" );

	_vec.data(0) = in1.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in1._ref );

	return( out );
}

// im_andimage_vec: bitwise and of an image with a vector constant
VImage VImage::andimage( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_andimage_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_orimage: bitwise or of two images
VImage VImage::orimage( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_orimage" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_orimageconst: bitwise or of an image with a constant
VImage VImage::orimage( int c ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_orimageconst" );

	_vec.data(0) = in1.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in1._ref );

	return( out );
}

// im_orimage_vec: bitwise or of an image with a vector constant
VImage VImage::orimage( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_orimage_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_eorimage: bitwise eor of two images
VImage VImage::eorimage( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_eorimage" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_eorimageconst: bitwise eor of an image with a constant
VImage VImage::eorimage( int c ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_eorimageconst" );

	_vec.data(0) = in1.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in1._ref );

	return( out );
}

// im_eorimage_vec: bitwise eor of an image with a vector constant
VImage VImage::eorimage( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_eorimage_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_shiftleft_vec: shift image array bits to left
VImage VImage::shiftleft( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_shiftleft_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_shiftleft: shift image n bits to left
VImage VImage::shiftleft( int c ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_shiftleft" );

	_vec.data(0) = in1.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in1._ref );

	return( out );
}

// im_shiftright_vec: shift image array bits to right
VImage VImage::shiftright( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_shiftright_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_shiftright: shift integer image n bits to right
VImage VImage::shiftright( int c ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_shiftright" );

	_vec.data(0) = in1.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in1._ref );

	return( out );
}


// bodies for package cimg
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_greyc: noise-removing filter
VImage VImage::greyc( int iterations, double amplitude, double sharpness, double anisotropy, double alpha, double sigma, double dl, double da, double gauss_prec, int interpolation, int fast_approx ) throw( VError )
{
	VImage src = *this;
	VImage dst;

	Vargv _vec( "im_greyc" );

	_vec.data(0) = src.image();
	_vec.data(1) = dst.image();
	*((int*) _vec.data(2)) = iterations;
	*((double*) _vec.data(3)) = amplitude;
	*((double*) _vec.data(4)) = sharpness;
	*((double*) _vec.data(5)) = anisotropy;
	*((double*) _vec.data(6)) = alpha;
	*((double*) _vec.data(7)) = sigma;
	*((double*) _vec.data(8)) = dl;
	*((double*) _vec.data(9)) = da;
	*((double*) _vec.data(10)) = gauss_prec;
	*((int*) _vec.data(11)) = interpolation;
	*((int*) _vec.data(12)) = fast_approx;
	_vec.call();
	dst._ref->addref( src._ref );

	return( dst );
}

// im_greyc_mask: noise-removing filter, with a mask
VImage VImage::greyc_mask( VImage mask, int iterations, double amplitude, double sharpness, double anisotropy, double alpha, double sigma, double dl, double da, double gauss_prec, int interpolation, int fast_approx ) throw( VError )
{
	VImage src = *this;
	VImage dst;

	Vargv _vec( "im_greyc_mask" );

	_vec.data(0) = src.image();
	_vec.data(1) = dst.image();
	_vec.data(2) = mask.image();
	*((int*) _vec.data(3)) = iterations;
	*((double*) _vec.data(4)) = amplitude;
	*((double*) _vec.data(5)) = sharpness;
	*((double*) _vec.data(6)) = anisotropy;
	*((double*) _vec.data(7)) = alpha;
	*((double*) _vec.data(8)) = sigma;
	*((double*) _vec.data(9)) = dl;
	*((double*) _vec.data(10)) = da;
	*((double*) _vec.data(11)) = gauss_prec;
	*((int*) _vec.data(12)) = interpolation;
	*((int*) _vec.data(13)) = fast_approx;
	_vec.call();
	dst._ref->addref( src._ref );
	dst._ref->addref( mask._ref );

	return( dst );
}


// bodies for package colour
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_LCh2Lab: convert LCh to Lab
VImage VImage::LCh2Lab() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LCh2Lab" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LCh2UCS: convert LCh to UCS
VImage VImage::LCh2UCS() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LCh2UCS" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2LCh: convert Lab to LCh
VImage VImage::Lab2LCh() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2LCh" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2LabQ: convert Lab to LabQ
VImage VImage::Lab2LabQ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2LabQ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2LabS: convert Lab to LabS
VImage VImage::Lab2LabS() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2LabS" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2UCS: convert Lab to UCS
VImage VImage::Lab2UCS() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2UCS" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2XYZ: convert D65 Lab to XYZ
VImage VImage::Lab2XYZ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2XYZ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2XYZ_temp: convert Lab to XYZ, with a specified colour temperature
VImage VImage::Lab2XYZ_temp( double X0, double Y0, double Z0 ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2XYZ_temp" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = X0;
	*((double*) _vec.data(3)) = Y0;
	*((double*) _vec.data(4)) = Z0;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Lab2disp: convert Lab to displayable
VImage VImage::Lab2disp( VDisplay disp ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Lab2disp" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = disp.disp();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LabQ2LabS: convert LabQ to LabS
VImage VImage::LabQ2LabS() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LabQ2LabS" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LabQ2Lab: convert LabQ to Lab
VImage VImage::LabQ2Lab() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LabQ2Lab" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LabQ2XYZ: convert LabQ to XYZ
VImage VImage::LabQ2XYZ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LabQ2XYZ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LabQ2disp: convert LabQ to displayable
VImage VImage::LabQ2disp( VDisplay disp ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LabQ2disp" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = disp.disp();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LabS2LabQ: convert LabS to LabQ
VImage VImage::LabS2LabQ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LabS2LabQ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_LabS2Lab: convert LabS to Lab
VImage VImage::LabS2Lab() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_LabS2Lab" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_UCS2LCh: convert UCS to LCh
VImage VImage::UCS2LCh() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_UCS2LCh" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_UCS2Lab: convert UCS to Lab
VImage VImage::UCS2Lab() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_UCS2Lab" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_UCS2XYZ: convert UCS to XYZ
VImage VImage::UCS2XYZ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_UCS2XYZ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_XYZ2Lab: convert D65 XYZ to Lab
VImage VImage::XYZ2Lab() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_XYZ2Lab" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_XYZ2Lab_temp: convert XYZ to Lab, with a specified colour temperature
VImage VImage::XYZ2Lab_temp( double X0, double Y0, double Z0 ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_XYZ2Lab_temp" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = X0;
	*((double*) _vec.data(3)) = Y0;
	*((double*) _vec.data(4)) = Z0;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_XYZ2UCS: convert XYZ to UCS
VImage VImage::XYZ2UCS() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_XYZ2UCS" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_XYZ2Yxy: convert XYZ to Yxy
VImage VImage::XYZ2Yxy() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_XYZ2Yxy" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_XYZ2disp: convert XYZ to displayble
VImage VImage::XYZ2disp( VDisplay disp ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_XYZ2disp" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = disp.disp();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_XYZ2sRGB: convert XYZ to sRGB
VImage VImage::XYZ2sRGB() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_XYZ2sRGB" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_Yxy2XYZ: convert Yxy to XYZ
VImage VImage::Yxy2XYZ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_Yxy2XYZ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_dE00_fromLab: calculate delta-E CIE2000 for two Lab images
VImage VImage::dE00_fromLab( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_dE00_fromLab" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_dECMC_fromLab: calculate delta-E CMC(1:1) for two Lab images
VImage VImage::dECMC_fromLab( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_dECMC_fromLab" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_dECMC_fromdisp: calculate delta-E CMC(1:1) for two displayable images
VImage VImage::dECMC_fromdisp( VImage in2, VDisplay disp ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_dECMC_fromdisp" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.data(3) = disp.disp();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_dE_fromLab: calculate delta-E for two Lab images
VImage VImage::dE_fromLab( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_dE_fromLab" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_dE_fromXYZ: calculate delta-E for two XYZ images
VImage VImage::dE_fromXYZ( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_dE_fromXYZ" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_dE_fromdisp: calculate delta-E for two displayable images
VImage VImage::dE_fromdisp( VImage in2, VDisplay disp ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_dE_fromdisp" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.data(3) = disp.disp();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_disp2Lab: convert displayable to Lab
VImage VImage::disp2Lab( VDisplay disp ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_disp2Lab" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = disp.disp();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_disp2XYZ: convert displayable to XYZ
VImage VImage::disp2XYZ( VDisplay disp ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_disp2XYZ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = disp.disp();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_float2rad: convert float to Radiance packed
VImage VImage::float2rad() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_float2rad" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_icc_ac2rc: convert LAB from AC to RC using an ICC profile
VImage VImage::icc_ac2rc( char* profile ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_icc_ac2rc" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = (im_object) profile;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_icc_export_depth: convert a float LAB to device space with an ICC profile
VImage VImage::icc_export_depth( int depth, char* output_profile, int intent ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_icc_export_depth" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = depth;
	_vec.data(3) = (im_object) output_profile;
	*((int*) _vec.data(4)) = intent;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_icc_import: convert a device image to float LAB with an ICC profile
VImage VImage::icc_import( char* input_profile, int intent ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_icc_import" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = (im_object) input_profile;
	*((int*) _vec.data(3)) = intent;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_icc_import_embedded: convert a device image to float LAB using the embedded profile
VImage VImage::icc_import_embedded( int intent ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_icc_import_embedded" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = intent;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_icc_transform: convert between two device images with a pair of ICC profiles
VImage VImage::icc_transform( char* input_profile, char* output_profile, int intent ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_icc_transform" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = (im_object) input_profile;
	_vec.data(3) = (im_object) output_profile;
	*((int*) _vec.data(4)) = intent;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lab_morph: morph colourspace of a LAB image
VImage VImage::lab_morph( VDMask greyscale, double L_offset, double L_scale, double a_scale, double b_scale ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lab_morph" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = greyscale.mask().dptr;
	*((double*) _vec.data(3)) = L_offset;
	*((double*) _vec.data(4)) = L_scale;
	*((double*) _vec.data(5)) = a_scale;
	*((double*) _vec.data(6)) = b_scale;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_rad2float: convert Radiance packed to float
VImage VImage::rad2float() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rad2float" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_sRGB2XYZ: convert sRGB to XYZ
VImage VImage::sRGB2XYZ() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_sRGB2XYZ" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}


// bodies for package conversion
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_addgnoise: add gaussian noise with mean 0 and std. dev. sigma
VImage VImage::addgnoise( double sigma ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_addgnoise" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = sigma;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_gaussnoise: generate image of gaussian noise with specified statistics
VImage VImage::gaussnoise( int xsize, int ysize, double mean, double sigma ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_gaussnoise" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = xsize;
	*((int*) _vec.data(2)) = ysize;
	*((double*) _vec.data(3)) = mean;
	*((double*) _vec.data(4)) = sigma;
	_vec.call();

	return( out );
}

// im_bandjoin: bandwise join of two images
VImage VImage::bandjoin( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_bandjoin" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_black: generate black image
VImage VImage::black( int x_size, int y_size, int bands ) throw( VError )
{
	VImage output;

	Vargv _vec( "im_black" );

	_vec.data(0) = output.image();
	*((int*) _vec.data(1)) = x_size;
	*((int*) _vec.data(2)) = y_size;
	*((int*) _vec.data(3)) = bands;
	_vec.call();

	return( output );
}

// im_c2amph: convert real and imaginary to phase and amplitude
VImage VImage::c2amph() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_c2amph" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_c2imag: extract imaginary part of complex image
VImage VImage::c2imag() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_c2imag" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_c2ps: find power spectrum of complex image
VImage VImage::c2ps() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_c2ps" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_c2real: extract real part of complex image
VImage VImage::c2real() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_c2real" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_c2rect: convert phase and amplitude to real and imaginary
VImage VImage::c2rect() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_c2rect" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_clip: convert to unsigned 8-bit integer
VImage VImage::clip() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_clip" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_clip2fmt: convert image format to ofmt
VImage VImage::clip2fmt( int ofmt ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_clip2fmt" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = ofmt;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_copy: copy image
VImage VImage::copy() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_copy" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_copy_file: copy image to a file and return that
VImage VImage::copy_file() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_copy_file" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_copy_morph: copy image, setting pixel layout
VImage VImage::copy_morph( int Bands, int BandFmt, int Coding ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_copy_morph" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = Bands;
	*((int*) _vec.data(3)) = BandFmt;
	*((int*) _vec.data(4)) = Coding;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_copy_swap: copy image, swapping byte order
VImage VImage::copy_swap() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_copy_swap" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_copy_set: copy image, setting informational fields
VImage VImage::copy_( int Type, double Xres, double Yres, int Xoffset, int Yoffset ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_copy_set" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = Type;
	*((double*) _vec.data(3)) = Xres;
	*((double*) _vec.data(4)) = Yres;
	*((int*) _vec.data(5)) = Xoffset;
	*((int*) _vec.data(6)) = Yoffset;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_extract_area: extract area
VImage VImage::extract_area( int left, int top, int width, int height ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_extract_area" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = left;
	*((int*) _vec.data(3)) = top;
	*((int*) _vec.data(4)) = width;
	*((int*) _vec.data(5)) = height;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_extract_areabands: extract area and bands
VImage VImage::extract_areabands( int left, int top, int width, int height, int band, int nbands ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_extract_areabands" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = left;
	*((int*) _vec.data(3)) = top;
	*((int*) _vec.data(4)) = width;
	*((int*) _vec.data(5)) = height;
	*((int*) _vec.data(6)) = band;
	*((int*) _vec.data(7)) = nbands;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_extract_band: extract band
VImage VImage::extract_band( int band ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_extract_band" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = band;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_extract_bands: extract several bands
VImage VImage::extract_bands( int band, int nbands ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_extract_bands" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = band;
	*((int*) _vec.data(3)) = nbands;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_extract: extract area/band
VImage VImage::extract( int left, int top, int width, int height, int band ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_extract" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = left;
	*((int*) _vec.data(3)) = top;
	*((int*) _vec.data(4)) = width;
	*((int*) _vec.data(5)) = height;
	*((int*) _vec.data(6)) = band;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_falsecolour: turn luminance changes into chrominance changes
VImage VImage::falsecolour() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_falsecolour" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_fliphor: flip image left-right
VImage VImage::fliphor() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_fliphor" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_flipver: flip image top-bottom
VImage VImage::flipver() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_flipver" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_gbandjoin: bandwise join of many images
VImage VImage::gbandjoin( std::vector<VImage> in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_gbandjoin" );

	((im_imagevec_object*) _vec.data(0))->n = in.size();
	((im_imagevec_object*) _vec.data(0))->vec = new IMAGE *[in.size()];
	for( unsigned int i = 0; i < in.size(); i++ )
		((im_imagevec_object*) _vec.data(0))->vec[i] = in[i].image();
	_vec.data(1) = out.image();
	_vec.call();
	for( unsigned int i = 0; i < in.size(); i++ )
		out._ref->addref( in[i]._ref );

	return( out );
}

// im_grid: chop a tall thin image into a grid of images
VImage VImage::grid( int tile_height, int across, int down ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_grid" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = tile_height;
	*((int*) _vec.data(3)) = across;
	*((int*) _vec.data(4)) = down;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_insert: insert sub-image into main image at position
VImage VImage::insert( VImage sub, int x, int y ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_insert" );

	_vec.data(0) = in.image();
	_vec.data(1) = sub.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = x;
	*((int*) _vec.data(4)) = y;
	_vec.call();
	out._ref->addref( in._ref );
	out._ref->addref( sub._ref );

	return( out );
}

// im_insertset: insert sub into main at every position in x, y
VImage VImage::insert( VImage sub, std::vector<int> x, std::vector<int> y ) throw( VError )
{
	VImage main = *this;
	VImage out;

	Vargv _vec( "im_insertset" );

	_vec.data(0) = main.image();
	_vec.data(1) = sub.image();
	_vec.data(2) = out.image();
	((im_intvec_object*) _vec.data(3))->n = x.size();
	((im_intvec_object*) _vec.data(3))->vec = new int[x.size()];
	for( unsigned int i = 0; i < x.size(); i++ )
		((im_intvec_object*) _vec.data(3))->vec[i] = x[i];
	((im_intvec_object*) _vec.data(4))->n = y.size();
	((im_intvec_object*) _vec.data(4))->vec = new int[y.size()];
	for( unsigned int i = 0; i < y.size(); i++ )
		((im_intvec_object*) _vec.data(4))->vec[i] = y[i];
	_vec.call();

	return( out );
}

// im_insert_noexpand: insert sub-image into main image at position, no expansion
VImage VImage::insert_noexpand( VImage sub, int x, int y ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_insert_noexpand" );

	_vec.data(0) = in.image();
	_vec.data(1) = sub.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = x;
	*((int*) _vec.data(4)) = y;
	_vec.call();
	out._ref->addref( in._ref );
	out._ref->addref( sub._ref );

	return( out );
}

// im_embed: embed in within a set of borders
VImage VImage::embed( int type, int x, int y, int w, int h ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_embed" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = type;
	*((int*) _vec.data(3)) = x;
	*((int*) _vec.data(4)) = y;
	*((int*) _vec.data(5)) = w;
	*((int*) _vec.data(6)) = h;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lrjoin: join two images left-right
VImage VImage::lrjoin( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_lrjoin" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_mask2vips: convert DOUBLEMASK to VIPS image
VImage VImage::mask2vips( VDMask input ) throw( VError )
{
	VImage output;

	Vargv _vec( "im_mask2vips" );

	((im_mask_object*) _vec.data(0))->mask = input.mask().dptr;
	_vec.data(1) = output.image();
	_vec.call();

	return( output );
}

// im_msb: convert to uchar by discarding bits
VImage VImage::msb() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_msb" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_msb_band: convert to single band uchar by discarding bits
VImage VImage::msb_band( int band ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_msb_band" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = band;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_replicate: replicate an image horizontally and vertically
VImage VImage::replicate( int across, int down ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_replicate" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = across;
	*((int*) _vec.data(3)) = down;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}

// im_ri2c: join two non-complex images to form complex
VImage VImage::ri2c( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_ri2c" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_rot180: rotate image 180 degrees
VImage VImage::rot180() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rot180" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_rot270: rotate image 270 degrees clockwise
VImage VImage::rot270() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rot270" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_rot90: rotate image 90 degrees clockwise
VImage VImage::rot90() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rot90" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_scale: scale image linearly to fit range 0-255
VImage VImage::scale() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_scale" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_scaleps: logarithmic scale of image to fit range 0-255
VImage VImage::scaleps() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_scaleps" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_subsample: subsample image by integer factors
VImage VImage::subsample( int xshrink, int yshrink ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_subsample" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = xshrink;
	*((int*) _vec.data(3)) = yshrink;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_system: run command on image
char* VImage::system( char* command ) throw( VError )
{
	VImage im = *this;
	char* output;

	Vargv _vec( "im_system" );

	_vec.data(0) = im.image();
	_vec.data(1) = (im_object) command;
	_vec.call();
	output = (char*) _vec.data(2);

	return( output );
}

// im_tbjoin: join two images top-bottom
VImage VImage::tbjoin( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_tbjoin" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_text: generate text image
VImage VImage::text( char* text, char* font, int width, int alignment, int dpi ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_text" );

	_vec.data(0) = out.image();
	_vec.data(1) = (im_object) text;
	_vec.data(2) = (im_object) font;
	*((int*) _vec.data(3)) = width;
	*((int*) _vec.data(4)) = alignment;
	*((int*) _vec.data(5)) = dpi;
	_vec.call();

	return( out );
}

// im_vips2mask: convert VIPS image to DOUBLEMASK
VDMask VImage::vips2mask() throw( VError )
{
	VImage input = *this;
	VDMask output;

	Vargv _vec( "im_vips2mask" );

	_vec.data(0) = input.image();
	((im_mask_object*) _vec.data(1))->name = (char*)"noname";
	_vec.call();
	output.embed( (DOUBLEMASK *)((im_mask_object*)_vec.data(1))->mask );

	return( output );
}

// im_wrap: shift image origin, wrapping at sides
VImage VImage::wrap( int x, int y ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_wrap" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = x;
	*((int*) _vec.data(3)) = y;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_zoom: simple zoom of an image by integer factors
VImage VImage::zoom( int xfac, int yfac ) throw( VError )
{
	VImage input = *this;
	VImage output;

	Vargv _vec( "im_zoom" );

	_vec.data(0) = input.image();
	_vec.data(1) = output.image();
	*((int*) _vec.data(2)) = xfac;
	*((int*) _vec.data(3)) = yfac;
	_vec.call();
	output._ref->addref( input._ref );

	return( output );
}


// bodies for package convolution
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_compass: convolve with 8-way rotating integer mask
VImage VImage::compass( VIMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_compass" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_contrast_surface: find high-contrast points in an image
VImage VImage::contrast_surface( int half_win_size, int spacing ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_contrast_surface" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = half_win_size;
	*((int*) _vec.data(3)) = spacing;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_conv: convolve
VImage VImage::conv( VIMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_conv" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_conv_f: convolve, with DOUBLEMASK
VImage VImage::conv( VDMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_conv_f" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().dptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_convsep: seperable convolution
VImage VImage::convsep( VIMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_convsep" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_convsep_f: seperable convolution, with DOUBLEMASK
VImage VImage::convsep( VDMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_convsep_f" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().dptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_fastcor: fast correlate in2 within in1
VImage VImage::fastcor( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_fastcor" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_gradcor: non-normalised correlation of gradient of in2 within in1
VImage VImage::gradcor( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_gradcor" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_gradient: convolve with 2-way rotating mask
VImage VImage::gradient( VIMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_gradient" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_grad_x: horizontal difference image
VImage VImage::grad_x() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_grad_x" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_grad_y: vertical difference image
VImage VImage::grad_y() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_grad_y" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lindetect: convolve with 4-way rotating mask
VImage VImage::lindetect( VIMask matrix ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lindetect" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = matrix.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_sharpen: sharpen high frequencies of L channel of LabQ
VImage VImage::sharpen( int mask_size, double x1, double y2, double y3, double m1, double m2 ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_sharpen" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = mask_size;
	*((double*) _vec.data(3)) = x1;
	*((double*) _vec.data(4)) = y2;
	*((double*) _vec.data(5)) = y3;
	*((double*) _vec.data(6)) = m1;
	*((double*) _vec.data(7)) = m2;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_spcor: normalised correlation of in2 within in1
VImage VImage::spcor( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_spcor" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}


// bodies for package format
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_csv2vips: read a file in csv format
VImage VImage::csv2vips( char* filename ) throw( VError )
{
	VImage im;

	Vargv _vec( "im_csv2vips" );

	_vec.data(0) = (im_object) filename;
	_vec.data(1) = im.image();
	_vec.call();

	return( im );
}

// im_jpeg2vips: convert from jpeg
VImage VImage::jpeg2vips( char* in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_jpeg2vips" );

	_vec.data(0) = (im_object) in;
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_magick2vips: load file with libMagick
VImage VImage::magick2vips( char* in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_magick2vips" );

	_vec.data(0) = (im_object) in;
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_png2vips: convert PNG file to VIPS image
VImage VImage::png2vips( char* in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_png2vips" );

	_vec.data(0) = (im_object) in;
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_exr2vips: convert an OpenEXR file to VIPS
VImage VImage::exr2vips( char* in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_exr2vips" );

	_vec.data(0) = (im_object) in;
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_ppm2vips: read a file in pbm/pgm/ppm format
VImage VImage::ppm2vips( char* filename ) throw( VError )
{
	VImage im;

	Vargv _vec( "im_ppm2vips" );

	_vec.data(0) = (im_object) filename;
	_vec.data(1) = im.image();
	_vec.call();

	return( im );
}

// im_analyze2vips: read a file in analyze format
VImage VImage::analyze2vips( char* filename ) throw( VError )
{
	VImage im;

	Vargv _vec( "im_analyze2vips" );

	_vec.data(0) = (im_object) filename;
	_vec.data(1) = im.image();
	_vec.call();

	return( im );
}

// im_tiff2vips: convert TIFF file to VIPS image
VImage VImage::tiff2vips( char* in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_tiff2vips" );

	_vec.data(0) = (im_object) in;
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_vips2csv: write an image in csv format
void VImage::vips2csv( char* filename ) throw( VError )
{
	VImage in = *this;
	Vargv _vec( "im_vips2csv" );

	_vec.data(0) = in.image();
	_vec.data(1) = (im_object) filename;
	_vec.call();
}

// im_vips2jpeg: convert to jpeg
void VImage::vips2jpeg( char* out ) throw( VError )
{
	VImage in = *this;
	Vargv _vec( "im_vips2jpeg" );

	_vec.data(0) = in.image();
	_vec.data(1) = (im_object) out;
	_vec.call();
}

// im_vips2mimejpeg: convert to jpeg as mime type on stdout
void VImage::vips2mimejpeg( int qfac ) throw( VError )
{
	VImage in = *this;
	Vargv _vec( "im_vips2mimejpeg" );

	_vec.data(0) = in.image();
	*((int*) _vec.data(1)) = qfac;
	_vec.call();
}

// im_vips2png: convert VIPS image to PNG file
void VImage::vips2png( char* out ) throw( VError )
{
	VImage in = *this;
	Vargv _vec( "im_vips2png" );

	_vec.data(0) = in.image();
	_vec.data(1) = (im_object) out;
	_vec.call();
}

// im_vips2ppm: write a file in pbm/pgm/ppm format
void VImage::vips2ppm( char* filename ) throw( VError )
{
	VImage im = *this;
	Vargv _vec( "im_vips2ppm" );

	_vec.data(0) = im.image();
	_vec.data(1) = (im_object) filename;
	_vec.call();
}

// im_vips2tiff: convert VIPS image to TIFF file
void VImage::vips2tiff( char* out ) throw( VError )
{
	VImage in = *this;
	Vargv _vec( "im_vips2tiff" );

	_vec.data(0) = in.image();
	_vec.data(1) = (im_object) out;
	_vec.call();
}


// bodies for package freq_filt
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_create_fmask: create frequency domain filter mask
VImage VImage::create_fmask( int width, int height, int type, double p1, double p2, double p3, double p4, double p5 ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_create_fmask" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = width;
	*((int*) _vec.data(2)) = height;
	*((int*) _vec.data(3)) = type;
	*((double*) _vec.data(4)) = p1;
	*((double*) _vec.data(5)) = p2;
	*((double*) _vec.data(6)) = p3;
	*((double*) _vec.data(7)) = p4;
	*((double*) _vec.data(8)) = p5;
	_vec.call();

	return( out );
}

// im_disp_ps: make displayable power spectrum
VImage VImage::disp_ps() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_disp_ps" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_flt_image_freq: frequency domain filter image
VImage VImage::flt_image_freq( int type, double p1, double p2, double p3, double p4, double p5 ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_flt_image_freq" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = type;
	*((double*) _vec.data(3)) = p1;
	*((double*) _vec.data(4)) = p2;
	*((double*) _vec.data(5)) = p3;
	*((double*) _vec.data(6)) = p4;
	*((double*) _vec.data(7)) = p5;
	_vec.call();

	return( out );
}

// im_fractsurf: generate a fractal surface of given dimension
VImage VImage::fractsurf( int size, double dimension ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_fractsurf" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = size;
	*((double*) _vec.data(2)) = dimension;
	_vec.call();

	return( out );
}

// im_freqflt: frequency-domain filter of in with mask
VImage VImage::freqflt( VImage mask ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_freqflt" );

	_vec.data(0) = in.image();
	_vec.data(1) = mask.image();
	_vec.data(2) = out.image();
	_vec.call();

	return( out );
}

// im_fwfft: forward fast-fourier transform
VImage VImage::fwfft() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_fwfft" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_rotquad: rotate image quadrants to move origin to centre
VImage VImage::rotquad() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rotquad" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_invfft: inverse fast-fourier transform
VImage VImage::invfft() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_invfft" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_phasecor_fft: non-normalised correlation of gradient of in2 within in1
VImage VImage::phasecor_fft( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_phasecor_fft" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();

	return( out );
}

// im_invfftr: real part of inverse fast-fourier transform
VImage VImage::invfftr() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_invfftr" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}


// bodies for package histograms_lut
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_gammacorrect: gamma-correct image
VImage VImage::gammacorrect( double exponent ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_gammacorrect" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = exponent;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_heq: histogram-equalise image
VImage VImage::heq( int band_number ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_heq" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = band_number;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_hist: find and graph histogram of image
VImage VImage::hist( int band_number ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_hist" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = band_number;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_histcum: turn histogram to cumulative histogram
VImage VImage::histcum() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histcum" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_histeq: form histogram equalistion LUT
VImage VImage::histeq() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histeq" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_hist_indexed: make a histogram with an index image
VImage VImage::hist_indexed( VImage value ) throw( VError )
{
	VImage index = *this;
	VImage out;

	Vargv _vec( "im_hist_indexed" );

	_vec.data(0) = index.image();
	_vec.data(1) = value.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( index._ref );
	out._ref->addref( value._ref );

	return( out );
}

// im_histgr: find histogram of image
VImage VImage::histgr( int band_number ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histgr" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = band_number;
	_vec.call();

	return( out );
}

// im_histnD: find 1D, 2D or 3D histogram of image
VImage VImage::histnD( int bins ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histnD" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = bins;
	_vec.call();

	return( out );
}

// im_histnorm: form normalised histogram
VImage VImage::histnorm() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histnorm" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_histplot: plot graph of histogram
VImage VImage::histplot() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histplot" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_histspec: find histogram which will make pdf of in match ref
VImage VImage::histspec( VImage ref ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_histspec" );

	_vec.data(0) = in.image();
	_vec.data(1) = ref.image();
	_vec.data(2) = out.image();
	_vec.call();

	return( out );
}

// im_hsp: match stats of in to stats of ref
VImage VImage::hsp( VImage ref ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_hsp" );

	_vec.data(0) = in.image();
	_vec.data(1) = ref.image();
	_vec.data(2) = out.image();
	_vec.call();

	return( out );
}

// im_identity: generate identity histogram
VImage VImage::identity( int nbands ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_identity" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = nbands;
	_vec.call();

	return( out );
}

// im_identity_ushort: generate ushort identity histogram
VImage VImage::identity_ushort( int nbands, int size ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_identity_ushort" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = nbands;
	*((int*) _vec.data(2)) = size;
	_vec.call();

	return( out );
}

// im_ismonotonic: test LUT for monotonicity
int VImage::ismonotonic() throw( VError )
{
	VImage lut = *this;
	int mono;

	Vargv _vec( "im_ismonotonic" );

	_vec.data(0) = lut.image();
	_vec.call();
	mono = *((int*)_vec.data(1));

	return( mono );
}

// im_lhisteq: local histogram equalisation
VImage VImage::lhisteq( int width, int height ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lhisteq" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = width;
	*((int*) _vec.data(3)) = height;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_mpercent: find threshold above which there are percent values
int VImage::mpercent( double percent ) throw( VError )
{
	VImage in = *this;
	int thresh;

	Vargv _vec( "im_mpercent" );

	_vec.data(0) = in.image();
	*((double*) _vec.data(1)) = percent;
	_vec.call();
	thresh = *((int*)_vec.data(2));

	return( thresh );
}

// im_invertlut: generate correction table from set of measures
VImage VImage::invertlut( VDMask measures, int lut_size ) throw( VError )
{
	VImage lut;

	Vargv _vec( "im_invertlut" );

	((im_mask_object*) _vec.data(0))->mask = measures.mask().dptr;
	_vec.data(1) = lut.image();
	*((int*) _vec.data(2)) = lut_size;
	_vec.call();

	return( lut );
}

// im_buildlut: generate LUT table from set of x/y positions
VImage VImage::buildlut( VDMask xyes ) throw( VError )
{
	VImage lut;

	Vargv _vec( "im_buildlut" );

	((im_mask_object*) _vec.data(0))->mask = xyes.mask().dptr;
	_vec.data(1) = lut.image();
	_vec.call();

	return( lut );
}

// im_maplut: map image through LUT
VImage VImage::maplut( VImage lut ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_maplut" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = lut.image();
	_vec.call();
	out._ref->addref( in._ref );
	out._ref->addref( lut._ref );

	return( out );
}

// im_project: find horizontal and vertical projections of an image
VImage VImage::project( VImage& vout ) throw( VError )
{
	VImage in = *this;
	VImage hout;

	Vargv _vec( "im_project" );

	_vec.data(0) = in.image();
	_vec.data(1) = hout.image();
	_vec.data(2) = vout.image();
	_vec.call();

	return( hout );
}

// im_stdif: statistical differencing
VImage VImage::stdif( double a, double m0, double b, double s0, int xw, int yw ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_stdif" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = a;
	*((double*) _vec.data(3)) = m0;
	*((double*) _vec.data(4)) = b;
	*((double*) _vec.data(5)) = s0;
	*((int*) _vec.data(6)) = xw;
	*((int*) _vec.data(7)) = yw;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_tone_analyse: analyse in and create LUT for tone adjustment
VImage VImage::tone_analyse( double Ps, double Pm, double Ph, double S, double M, double H ) throw( VError )
{
	VImage in = *this;
	VImage hist;

	Vargv _vec( "im_tone_analyse" );

	_vec.data(0) = in.image();
	_vec.data(1) = hist.image();
	*((double*) _vec.data(2)) = Ps;
	*((double*) _vec.data(3)) = Pm;
	*((double*) _vec.data(4)) = Ph;
	*((double*) _vec.data(5)) = S;
	*((double*) _vec.data(6)) = M;
	*((double*) _vec.data(7)) = H;
	_vec.call();

	return( hist );
}

// im_tone_build: create LUT for tone adjustment of LabS images
VImage VImage::tone_build( double Lb, double Lw, double Ps, double Pm, double Ph, double S, double M, double H ) throw( VError )
{
	VImage hist;

	Vargv _vec( "im_tone_build" );

	_vec.data(0) = hist.image();
	*((double*) _vec.data(1)) = Lb;
	*((double*) _vec.data(2)) = Lw;
	*((double*) _vec.data(3)) = Ps;
	*((double*) _vec.data(4)) = Pm;
	*((double*) _vec.data(5)) = Ph;
	*((double*) _vec.data(6)) = S;
	*((double*) _vec.data(7)) = M;
	*((double*) _vec.data(8)) = H;
	_vec.call();

	return( hist );
}

// im_tone_build_range: create LUT for tone adjustment
VImage VImage::tone_build_range( int in_max, int out_max, double Lb, double Lw, double Ps, double Pm, double Ph, double S, double M, double H ) throw( VError )
{
	VImage hist;

	Vargv _vec( "im_tone_build_range" );

	_vec.data(0) = hist.image();
	*((int*) _vec.data(1)) = in_max;
	*((int*) _vec.data(2)) = out_max;
	*((double*) _vec.data(3)) = Lb;
	*((double*) _vec.data(4)) = Lw;
	*((double*) _vec.data(5)) = Ps;
	*((double*) _vec.data(6)) = Pm;
	*((double*) _vec.data(7)) = Ph;
	*((double*) _vec.data(8)) = S;
	*((double*) _vec.data(9)) = M;
	*((double*) _vec.data(10)) = H;
	_vec.call();

	return( hist );
}

// im_tone_map: map L channel of LabS or LabQ image through LUT
VImage VImage::tone_map( VImage lut ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_tone_map" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = lut.image();
	_vec.call();
	out._ref->addref( in._ref );
	out._ref->addref( lut._ref );

	return( out );
}


// bodies for package inplace
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_circle: plot circle on image
void VImage::circle( int cx, int cy, int radius, int intensity ) throw( VError )
{
	VImage image = *this;
	Vargv _vec( "im_circle" );

	_vec.data(0) = image.image();
	*((int*) _vec.data(1)) = cx;
	*((int*) _vec.data(2)) = cy;
	*((int*) _vec.data(3)) = radius;
	*((int*) _vec.data(4)) = intensity;
	_vec.call();
}

// im_flood_blob_copy: flood with ink from start_x, start_y while pixel == start pixel
VImage VImage::flood_blob_copy( int start_x, int start_y, std::vector<double> ink ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_flood_blob_copy" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = start_x;
	*((int*) _vec.data(3)) = start_y;
	((im_doublevec_object*) _vec.data(4))->n = ink.size();
	((im_doublevec_object*) _vec.data(4))->vec = new double[ink.size()];
	for( unsigned int i = 0; i < ink.size(); i++ )
		((im_doublevec_object*) _vec.data(4))->vec[i] = ink[i];
	_vec.call();

	return( out );
}

// im_flood_other_copy: flood mask with serial number from start_x, start_y while pixel == start pixel
VImage VImage::flood_other_copy( VImage test, int start_x, int start_y, int serial ) throw( VError )
{
	VImage mask = *this;
	VImage out;

	Vargv _vec( "im_flood_other_copy" );

	_vec.data(0) = mask.image();
	_vec.data(1) = test.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = start_x;
	*((int*) _vec.data(4)) = start_y;
	*((int*) _vec.data(5)) = serial;
	_vec.call();

	return( out );
}

// im_insertplace: draw image sub inside image main at position (x,y)
void VImage::insertplace( VImage sub, int x, int y ) throw( VError )
{
	VImage main = *this;
	Vargv _vec( "im_insertplace" );

	_vec.data(0) = main.image();
	_vec.data(1) = sub.image();
	*((int*) _vec.data(2)) = x;
	*((int*) _vec.data(3)) = y;
	_vec.call();
}

// im_lineset: draw line between points (x1,y1) and (x2,y2)
VImage VImage::line( VImage mask, VImage ink, std::vector<int> x1, std::vector<int> y1, std::vector<int> x2, std::vector<int> y2 ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lineset" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = mask.image();
	_vec.data(3) = ink.image();
	((im_intvec_object*) _vec.data(4))->n = x1.size();
	((im_intvec_object*) _vec.data(4))->vec = new int[x1.size()];
	for( unsigned int i = 0; i < x1.size(); i++ )
		((im_intvec_object*) _vec.data(4))->vec[i] = x1[i];
	((im_intvec_object*) _vec.data(5))->n = y1.size();
	((im_intvec_object*) _vec.data(5))->vec = new int[y1.size()];
	for( unsigned int i = 0; i < y1.size(); i++ )
		((im_intvec_object*) _vec.data(5))->vec[i] = y1[i];
	((im_intvec_object*) _vec.data(6))->n = x2.size();
	((im_intvec_object*) _vec.data(6))->vec = new int[x2.size()];
	for( unsigned int i = 0; i < x2.size(); i++ )
		((im_intvec_object*) _vec.data(6))->vec[i] = x2[i];
	((im_intvec_object*) _vec.data(7))->n = y2.size();
	((im_intvec_object*) _vec.data(7))->vec = new int[y2.size()];
	for( unsigned int i = 0; i < y2.size(); i++ )
		((im_intvec_object*) _vec.data(7))->vec[i] = y2[i];
	_vec.call();

	return( out );
}


// bodies for package iofuncs
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_binfile: open a headerless binary file
VImage VImage::binfile( char* filename, int width, int height, int bands, int offset ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_binfile" );

	_vec.data(0) = (im_object) filename;
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = width;
	*((int*) _vec.data(3)) = height;
	*((int*) _vec.data(4)) = bands;
	*((int*) _vec.data(5)) = offset;
	_vec.call();

	return( out );
}

// im_cache: cache results of an operation
VImage VImage::cache( int tile_width, int tile_height, int max_tiles ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_cache" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = tile_width;
	*((int*) _vec.data(3)) = tile_height;
	*((int*) _vec.data(4)) = max_tiles;
	_vec.call();

	return( out );
}

// im_getext: return the image metadata XML as a string
char* VImage::getext() throw( VError )
{
	VImage image = *this;
	char* history;

	Vargv _vec( "im_getext" );

	_vec.data(0) = image.image();
	_vec.call();
	history = (char*) _vec.data(1);

	return( history );
}

// im_header_get_typeof: return field type
int VImage::header_get_typeof( char* field ) throw( VError )
{
	VImage image = *this;
	int gtype;

	Vargv _vec( "im_header_get_typeof" );

	_vec.data(0) = (im_object) field;
	_vec.data(1) = image.image();
	_vec.call();
	gtype = *((int*)_vec.data(2));

	return( gtype );
}

// im_header_int: extract int fields from header
int VImage::header_int( char* field ) throw( VError )
{
	VImage image = *this;
	int value;

	Vargv _vec( "im_header_int" );

	_vec.data(0) = (im_object) field;
	_vec.data(1) = image.image();
	_vec.call();
	value = *((int*)_vec.data(2));

	return( value );
}

// im_header_double: extract double fields from header
double VImage::header_double( char* field ) throw( VError )
{
	VImage image = *this;
	double value;

	Vargv _vec( "im_header_double" );

	_vec.data(0) = (im_object) field;
	_vec.data(1) = image.image();
	_vec.call();
	value = *((double*)_vec.data(2));

	return( value );
}

// im_header_string: extract fields from headers as strings
char* VImage::header_string( char* field ) throw( VError )
{
	VImage image = *this;
	char* value;

	Vargv _vec( "im_header_string" );

	_vec.data(0) = (im_object) field;
	_vec.data(1) = image.image();
	_vec.call();
	value = (char*) _vec.data(2);

	return( value );
}

// im_history_get: return the image history as a string
char* VImage::history_get() throw( VError )
{
	VImage image = *this;
	char* history;

	Vargv _vec( "im_history_get" );

	_vec.data(0) = image.image();
	_vec.call();
	history = (char*) _vec.data(1);

	return( history );
}

// im_printdesc: print an image header to stdout
void VImage::printdesc() throw( VError )
{
	VImage image = *this;
	Vargv _vec( "im_printdesc" );

	_vec.data(0) = image.image();
	_vec.call();
}


// bodies for package mask
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009

// bodies for package morphology
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_cntlines: count horizontal or vertical lines
double VImage::cntlines( int direction ) throw( VError )
{
	VImage in = *this;
	double nlines;

	Vargv _vec( "im_cntlines" );

	_vec.data(0) = in.image();
	*((int*) _vec.data(2)) = direction;
	_vec.call();
	nlines = *((double*)_vec.data(1));

	return( nlines );
}

// im_dilate: dilate image with mask, adding a black border
VImage VImage::dilate( VIMask mask ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_dilate" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = mask.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_rank: rank filter nth element of xsize/ysize window
VImage VImage::rank( int xsize, int ysize, int n ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rank" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = xsize;
	*((int*) _vec.data(3)) = ysize;
	*((int*) _vec.data(4)) = n;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_rank_image: point-wise pixel rank
VImage VImage::rank_image( std::vector<VImage> in, int index ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_rank_image" );

	((im_imagevec_object*) _vec.data(0))->n = in.size();
	((im_imagevec_object*) _vec.data(0))->vec = new IMAGE *[in.size()];
	for( unsigned int i = 0; i < in.size(); i++ )
		((im_imagevec_object*) _vec.data(0))->vec[i] = in[i].image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = index;
	_vec.call();
	for( unsigned int i = 0; i < in.size(); i++ )
		out._ref->addref( in[i]._ref );

	return( out );
}

// im_maxvalue: point-wise maximum value
VImage VImage::maxvalue( std::vector<VImage> in ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_maxvalue" );

	((im_imagevec_object*) _vec.data(0))->n = in.size();
	((im_imagevec_object*) _vec.data(0))->vec = new IMAGE *[in.size()];
	for( unsigned int i = 0; i < in.size(); i++ )
		((im_imagevec_object*) _vec.data(0))->vec[i] = in[i].image();
	_vec.data(1) = out.image();
	_vec.call();
	for( unsigned int i = 0; i < in.size(); i++ )
		out._ref->addref( in[i]._ref );

	return( out );
}

// im_label_regions: number continuous regions in an image
VImage VImage::label_regions( int& segments ) throw( VError )
{
	VImage test = *this;
	VImage mask;

	Vargv _vec( "im_label_regions" );

	_vec.data(0) = test.image();
	_vec.data(1) = mask.image();
	_vec.call();
	segments = *((int*)_vec.data(2));

	return( mask );
}

// im_zerox: find +ve or -ve zero crossings in image
VImage VImage::zerox( int flag ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_zerox" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = flag;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_erode: erode image with mask, adding a black border
VImage VImage::erode( VIMask mask ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_erode" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_mask_object*) _vec.data(2))->mask = mask.mask().iptr;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_profile: find first horizontal/vertical edge
VImage VImage::profile( int direction ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_profile" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = direction;
	_vec.call();

	return( out );
}


// bodies for package mosaicing
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_align_bands: align the bands of an image
VImage VImage::align_bands() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_align_bands" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();

	return( out );
}

// im_correl: search area around sec for match for area around ref
double VImage::correl( VImage sec, int xref, int yref, int xsec, int ysec, int hwindowsize, int hsearchsize, int& x, int& y ) throw( VError )
{
	VImage ref = *this;
	double correlation;

	Vargv _vec( "im_correl" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	*((int*) _vec.data(2)) = xref;
	*((int*) _vec.data(3)) = yref;
	*((int*) _vec.data(4)) = xsec;
	*((int*) _vec.data(5)) = ysec;
	*((int*) _vec.data(6)) = hwindowsize;
	*((int*) _vec.data(7)) = hsearchsize;
	_vec.call();
	correlation = *((double*)_vec.data(8));
	x = *((int*)_vec.data(9));
	y = *((int*)_vec.data(10));

	return( correlation );
}

// im__find_lroverlap: search for left-right overlap of ref and sec
int VImage::_find_lroverlap( VImage sec, int bandno, int xr, int yr, int xs, int ys, int halfcorrelation, int halfarea, int& dy0, double& scale1, double& angle1, double& dx1, double& dy1 ) throw( VError )
{
	VImage ref = *this;
	int dx0;

	Vargv _vec( "im__find_lroverlap" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	*((int*) _vec.data(2)) = bandno;
	*((int*) _vec.data(3)) = xr;
	*((int*) _vec.data(4)) = yr;
	*((int*) _vec.data(5)) = xs;
	*((int*) _vec.data(6)) = ys;
	*((int*) _vec.data(7)) = halfcorrelation;
	*((int*) _vec.data(8)) = halfarea;
	_vec.call();
	dx0 = *((int*)_vec.data(9));
	dy0 = *((int*)_vec.data(10));
	scale1 = *((double*)_vec.data(11));
	angle1 = *((double*)_vec.data(12));
	dx1 = *((double*)_vec.data(13));
	dy1 = *((double*)_vec.data(14));

	return( dx0 );
}

// im__find_tboverlap: search for top-bottom overlap of ref and sec
int VImage::_find_tboverlap( VImage sec, int bandno, int xr, int yr, int xs, int ys, int halfcorrelation, int halfarea, int& dy0, double& scale1, double& angle1, double& dx1, double& dy1 ) throw( VError )
{
	VImage ref = *this;
	int dx0;

	Vargv _vec( "im__find_tboverlap" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	*((int*) _vec.data(2)) = bandno;
	*((int*) _vec.data(3)) = xr;
	*((int*) _vec.data(4)) = yr;
	*((int*) _vec.data(5)) = xs;
	*((int*) _vec.data(6)) = ys;
	*((int*) _vec.data(7)) = halfcorrelation;
	*((int*) _vec.data(8)) = halfarea;
	_vec.call();
	dx0 = *((int*)_vec.data(9));
	dy0 = *((int*)_vec.data(10));
	scale1 = *((double*)_vec.data(11));
	angle1 = *((double*)_vec.data(12));
	dx1 = *((double*)_vec.data(13));
	dy1 = *((double*)_vec.data(14));

	return( dx0 );
}

// im_global_balance: automatically rebuild mosaic with balancing
VImage VImage::global_balance( double gamma ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_global_balance" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = gamma;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_global_balancef: automatically rebuild mosaic with balancing, float output
VImage VImage::global_balancef( double gamma ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_global_balancef" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = gamma;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lrmerge: left-right merge of in1 and in2
VImage VImage::lrmerge( VImage sec, int dx, int dy, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_lrmerge" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = dx;
	*((int*) _vec.data(4)) = dy;
	*((int*) _vec.data(5)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_lrmerge1: first-order left-right merge of ref and sec
VImage VImage::lrmerge1( VImage sec, int xr1, int yr1, int xs1, int ys1, int xr2, int yr2, int xs2, int ys2, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_lrmerge1" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = xr1;
	*((int*) _vec.data(4)) = yr1;
	*((int*) _vec.data(5)) = xs1;
	*((int*) _vec.data(6)) = ys1;
	*((int*) _vec.data(7)) = xr2;
	*((int*) _vec.data(8)) = yr2;
	*((int*) _vec.data(9)) = xs2;
	*((int*) _vec.data(10)) = ys2;
	*((int*) _vec.data(11)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_lrmosaic: left-right mosaic of ref and sec
VImage VImage::lrmosaic( VImage sec, int bandno, int xr, int yr, int xs, int ys, int halfcorrelation, int halfarea, int balancetype, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_lrmosaic" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = bandno;
	*((int*) _vec.data(4)) = xr;
	*((int*) _vec.data(5)) = yr;
	*((int*) _vec.data(6)) = xs;
	*((int*) _vec.data(7)) = ys;
	*((int*) _vec.data(8)) = halfcorrelation;
	*((int*) _vec.data(9)) = halfarea;
	*((int*) _vec.data(10)) = balancetype;
	*((int*) _vec.data(11)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_lrmosaic1: first-order left-right mosaic of ref and sec
VImage VImage::lrmosaic1( VImage sec, int bandno, int xr1, int yr1, int xs1, int ys1, int xr2, int yr2, int xs2, int ys2, int halfcorrelation, int halfarea, int balancetype, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_lrmosaic1" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = bandno;
	*((int*) _vec.data(4)) = xr1;
	*((int*) _vec.data(5)) = yr1;
	*((int*) _vec.data(6)) = xs1;
	*((int*) _vec.data(7)) = ys1;
	*((int*) _vec.data(8)) = xr2;
	*((int*) _vec.data(9)) = yr2;
	*((int*) _vec.data(10)) = xs2;
	*((int*) _vec.data(11)) = ys2;
	*((int*) _vec.data(12)) = halfcorrelation;
	*((int*) _vec.data(13)) = halfarea;
	*((int*) _vec.data(14)) = balancetype;
	*((int*) _vec.data(15)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_match_linear: resample ref so that tie-points match
VImage VImage::match_linear( VImage sec, int xref1, int yref1, int xsec1, int ysec1, int xref2, int yref2, int xsec2, int ysec2 ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_match_linear" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = xref1;
	*((int*) _vec.data(4)) = yref1;
	*((int*) _vec.data(5)) = xsec1;
	*((int*) _vec.data(6)) = ysec1;
	*((int*) _vec.data(7)) = xref2;
	*((int*) _vec.data(8)) = yref2;
	*((int*) _vec.data(9)) = xsec2;
	*((int*) _vec.data(10)) = ysec2;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_match_linear_search: search sec, then resample so that tie-points match
VImage VImage::match_linear_search( VImage sec, int xref1, int yref1, int xsec1, int ysec1, int xref2, int yref2, int xsec2, int ysec2, int hwindowsize, int hsearchsize ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_match_linear_search" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = xref1;
	*((int*) _vec.data(4)) = yref1;
	*((int*) _vec.data(5)) = xsec1;
	*((int*) _vec.data(6)) = ysec1;
	*((int*) _vec.data(7)) = xref2;
	*((int*) _vec.data(8)) = yref2;
	*((int*) _vec.data(9)) = xsec2;
	*((int*) _vec.data(10)) = ysec2;
	*((int*) _vec.data(11)) = hwindowsize;
	*((int*) _vec.data(12)) = hsearchsize;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_maxpos_subpel: subpixel position of maximum of (phase correlation) image
double VImage::maxpos_subpel( double& y ) throw( VError )
{
	VImage im = *this;
	double x;

	Vargv _vec( "im_maxpos_subpel" );

	_vec.data(0) = im.image();
	_vec.call();
	x = *((double*)_vec.data(1));
	y = *((double*)_vec.data(2));

	return( x );
}

// im_remosaic: automatically rebuild mosaic with new files
VImage VImage::remosaic( char* old_str, char* new_str ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_remosaic" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.data(2) = (im_object) old_str;
	_vec.data(3) = (im_object) new_str;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_tbmerge: top-bottom merge of in1 and in2
VImage VImage::tbmerge( VImage sec, int dx, int dy, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_tbmerge" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = dx;
	*((int*) _vec.data(4)) = dy;
	*((int*) _vec.data(5)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_tbmerge1: first-order top-bottom merge of in1 and in2
VImage VImage::tbmerge1( VImage sec, int xr1, int yr1, int xs1, int ys1, int xr2, int yr2, int xs2, int ys2, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_tbmerge1" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = xr1;
	*((int*) _vec.data(4)) = yr1;
	*((int*) _vec.data(5)) = xs1;
	*((int*) _vec.data(6)) = ys1;
	*((int*) _vec.data(7)) = xr2;
	*((int*) _vec.data(8)) = yr2;
	*((int*) _vec.data(9)) = xs2;
	*((int*) _vec.data(10)) = ys2;
	*((int*) _vec.data(11)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_tbmosaic: top-bottom mosaic of in1 and in2
VImage VImage::tbmosaic( VImage sec, int bandno, int xr, int yr, int xs, int ys, int halfcorrelation, int halfarea, int balancetype, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_tbmosaic" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = bandno;
	*((int*) _vec.data(4)) = xr;
	*((int*) _vec.data(5)) = yr;
	*((int*) _vec.data(6)) = xs;
	*((int*) _vec.data(7)) = ys;
	*((int*) _vec.data(8)) = halfcorrelation;
	*((int*) _vec.data(9)) = halfarea;
	*((int*) _vec.data(10)) = balancetype;
	*((int*) _vec.data(11)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}

// im_tbmosaic1: first-order top-bottom mosaic of ref and sec
VImage VImage::tbmosaic1( VImage sec, int bandno, int xr1, int yr1, int xs1, int ys1, int xr2, int yr2, int xs2, int ys2, int halfcorrelation, int halfarea, int balancetype, int mwidth ) throw( VError )
{
	VImage ref = *this;
	VImage out;

	Vargv _vec( "im_tbmosaic1" );

	_vec.data(0) = ref.image();
	_vec.data(1) = sec.image();
	_vec.data(2) = out.image();
	*((int*) _vec.data(3)) = bandno;
	*((int*) _vec.data(4)) = xr1;
	*((int*) _vec.data(5)) = yr1;
	*((int*) _vec.data(6)) = xs1;
	*((int*) _vec.data(7)) = ys1;
	*((int*) _vec.data(8)) = xr2;
	*((int*) _vec.data(9)) = yr2;
	*((int*) _vec.data(10)) = xs2;
	*((int*) _vec.data(11)) = ys2;
	*((int*) _vec.data(12)) = halfcorrelation;
	*((int*) _vec.data(13)) = halfarea;
	*((int*) _vec.data(14)) = balancetype;
	*((int*) _vec.data(15)) = mwidth;
	_vec.call();
	out._ref->addref( ref._ref );
	out._ref->addref( sec._ref );

	return( out );
}


// bodies for package other
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_benchmark: do something complicated for testing
VImage VImage::benchmark() throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_benchmark" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_benchmark2: do something complicated for testing
double VImage::benchmark2() throw( VError )
{
	VImage in = *this;
	double value;

	Vargv _vec( "im_benchmark2" );

	_vec.data(0) = in.image();
	_vec.call();
	value = *((double*)_vec.data(1));

	return( value );
}

// im_benchmarkn: do something complicated for testing
VImage VImage::benchmarkn( int n ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_benchmarkn" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = n;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_eye: generate IM_BANDFMT_UCHAR [0,255] frequency/amplitude image
VImage VImage::eye( int xsize, int ysize, double factor ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_eye" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = xsize;
	*((int*) _vec.data(2)) = ysize;
	*((double*) _vec.data(3)) = factor;
	_vec.call();

	return( out );
}

// im_grey: generate IM_BANDFMT_UCHAR [0,255] grey scale image
VImage VImage::grey( int xsize, int ysize ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_grey" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = xsize;
	*((int*) _vec.data(2)) = ysize;
	_vec.call();

	return( out );
}

// im_feye: generate IM_BANDFMT_FLOAT [-1,1] frequency/amplitude image
VImage VImage::feye( int xsize, int ysize, double factor ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_feye" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = xsize;
	*((int*) _vec.data(2)) = ysize;
	*((double*) _vec.data(3)) = factor;
	_vec.call();

	return( out );
}

// im_fgrey: generate IM_BANDFMT_FLOAT [0,1] grey scale image
VImage VImage::fgrey( int xsize, int ysize ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_fgrey" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = xsize;
	*((int*) _vec.data(2)) = ysize;
	_vec.call();

	return( out );
}

// im_fzone: generate IM_BANDFMT_FLOAT [-1,1] zone plate image
VImage VImage::fzone( int size ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_fzone" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = size;
	_vec.call();

	return( out );
}

// im_make_xy: generate image with pixel value equal to coordinate
VImage VImage::make_xy( int xsize, int ysize ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_make_xy" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = xsize;
	*((int*) _vec.data(2)) = ysize;
	_vec.call();

	return( out );
}

// im_zone: generate IM_BANDFMT_UCHAR [0,255] zone plate image
VImage VImage::zone( int size ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_zone" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = size;
	_vec.call();

	return( out );
}


// bodies for package relational
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_blend: use cond image to blend between images in1 and in2
VImage VImage::blend( VImage in1, VImage in2 ) throw( VError )
{
	VImage cond = *this;
	VImage out;

	Vargv _vec( "im_blend" );

	_vec.data(0) = cond.image();
	_vec.data(1) = in1.image();
	_vec.data(2) = in2.image();
	_vec.data(3) = out.image();
	_vec.call();
	out._ref->addref( cond._ref );
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_equal: two images equal in value
VImage VImage::equal( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_equal" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_equal_vec: image equals doublevec
VImage VImage::equal( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_equal_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_equalconst: image equals const
VImage VImage::equal( double c ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_equalconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_ifthenelse: use cond image to choose pels from image in1 or in2
VImage VImage::ifthenelse( VImage in1, VImage in2 ) throw( VError )
{
	VImage cond = *this;
	VImage out;

	Vargv _vec( "im_ifthenelse" );

	_vec.data(0) = cond.image();
	_vec.data(1) = in1.image();
	_vec.data(2) = in2.image();
	_vec.data(3) = out.image();
	_vec.call();
	out._ref->addref( cond._ref );
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_less: in1 less than in2 in value
VImage VImage::less( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_less" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_less_vec: in less than doublevec
VImage VImage::less( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_less_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lessconst: in less than const
VImage VImage::less( double c ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lessconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lesseq: in1 less than or equal to in2 in value
VImage VImage::lesseq( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_lesseq" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_lesseq_vec: in less than or equal to doublevec
VImage VImage::lesseq( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lesseq_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_lesseqconst: in less than or equal to const
VImage VImage::lesseq( double c ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_lesseqconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_more: in1 more than in2 in value
VImage VImage::more( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_more" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_more_vec: in more than doublevec
VImage VImage::more( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_more_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_moreconst: in more than const
VImage VImage::more( double c ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_moreconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_moreeq: in1 more than or equal to in2 in value
VImage VImage::moreeq( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_moreeq" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_moreeq_vec: in more than or equal to doublevec
VImage VImage::moreeq( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_moreeq_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_moreeqconst: in more than or equal to const
VImage VImage::moreeq( double c ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_moreeqconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_notequal: two images not equal in value
VImage VImage::notequal( VImage in2 ) throw( VError )
{
	VImage in1 = *this;
	VImage out;

	Vargv _vec( "im_notequal" );

	_vec.data(0) = in1.image();
	_vec.data(1) = in2.image();
	_vec.data(2) = out.image();
	_vec.call();
	out._ref->addref( in1._ref );
	out._ref->addref( in2._ref );

	return( out );
}

// im_notequal_vec: image does not equal doublevec
VImage VImage::notequal( std::vector<double> vec ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_notequal_vec" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	((im_doublevec_object*) _vec.data(2))->n = vec.size();
	((im_doublevec_object*) _vec.data(2))->vec = new double[vec.size()];
	for( unsigned int i = 0; i < vec.size(); i++ )
		((im_doublevec_object*) _vec.data(2))->vec[i] = vec[i];
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_notequalconst: image does not equal const
VImage VImage::notequal( double c ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_notequalconst" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = c;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}


// bodies for package resample
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_rightshift_size: decrease size by a power-of-two factor
VImage VImage::rightshift_size( int xshift, int yshift, int band_fmt ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_rightshift_size" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((int*) _vec.data(2)) = xshift;
	*((int*) _vec.data(3)) = yshift;
	*((int*) _vec.data(4)) = band_fmt;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_shrink: shrink image by xfac, yfac times
VImage VImage::shrink( double xfac, double yfac ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_shrink" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = xfac;
	*((double*) _vec.data(3)) = yfac;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}

// im_stretch3: stretch 3%, sub-pixel displace by xdisp/ydisp
VImage VImage::stretch3( double xdisp, double ydisp ) throw( VError )
{
	VImage in = *this;
	VImage out;

	Vargv _vec( "im_stretch3" );

	_vec.data(0) = in.image();
	_vec.data(1) = out.image();
	*((double*) _vec.data(2)) = xdisp;
	*((double*) _vec.data(3)) = ydisp;
	_vec.call();
	out._ref->addref( in._ref );

	return( out );
}


// bodies for package video
// this file automatically generated from
// VIPS library 7.20.1-Fri Nov 13 11:00:09 GMT 2009
// im_video_test: test video grabber
VImage VImage::video_test( int brightness, int error ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_video_test" );

	_vec.data(0) = out.image();
	*((int*) _vec.data(1)) = brightness;
	*((int*) _vec.data(2)) = error;
	_vec.call();

	return( out );
}

// im_video_v4l1: grab a video frame with v4l1
VImage VImage::video_v4l1( char* device, int channel, int brightness, int colour, int contrast, int hue, int ngrabs ) throw( VError )
{
	VImage out;

	Vargv _vec( "im_video_v4l1" );

	_vec.data(0) = out.image();
	_vec.data(1) = (im_object) device;
	*((int*) _vec.data(2)) = channel;
	*((int*) _vec.data(3)) = brightness;
	*((int*) _vec.data(4)) = colour;
	*((int*) _vec.data(5)) = contrast;
	*((int*) _vec.data(6)) = hue;
	*((int*) _vec.data(7)) = ngrabs;
	_vec.call();

	return( out );
}


