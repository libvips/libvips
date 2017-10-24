/* VIPS mask class.
 *
 * Just like VImage, but we don't need dependency stuff. Instead, have a base
 * wrapper over *MASK, derive VMaskD and VMaskI from that, and then put
 * refcounting over all of them.
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

#ifndef IM_VMASK_H
#define IM_VMASK_H

/* SWIG includes this file directly rather than going through vipscpp.h ... so
 * we have to define these macros here as well.
 */
#ifdef SWIG
# define VIPS_NAMESPACE_START namespace vips {
# define VIPS_NAMESPACE_END }
#endif /*SWIG*/

/* Don't include these when parsing for SWIG.
 */
#ifndef SWIG
# include <cstdarg>
# include <iosfwd>
# include <vector>
#endif /*!SWIG*/

/* Wrap pointers to these, but we don't want to import all the old C API. Just 
 * declare them.
 */
extern "C" {
	struct im__INTMASK;
	struct im__DOUBLEMASK;
}

VIPS_NAMESPACE_START

/* This first section is private. Only expose the non-P versions of these
 * classes later on. Don't need to wrap then in SWIG either.
 */
#ifndef SWIG
namespace _private_detail { 

union MASKUNION {
       im__INTMASK *iptr;
       im__DOUBLEMASK *dptr;
}; 

// Private wrapper over *MASK - user does not see this
class VPMask {
	friend class VMask;

public:
	// Track type of mask with this
	enum VMaskType {
		UNASSIGNED,		// Not yet set
		INT,			// mask points to INTMASK
		DOUBLE			// mask points to DOUBLEMASK
	};

	MASKUNION data;			// Mask pointer - INT or DOUBLE
	VMaskType type;			// Track type too, for safety

	virtual ~VPMask() {};

	// Duplicate
	virtual VPMask *dup() const = 0;

	// Projection functions to get MASK fields
	virtual int xsize() const = 0;
	virtual int ysize() const = 0;
	virtual const char *filename() const = 0;

	// Output
	virtual void ostream_print( std::ostream & ) const = 0;
};

// Specialise for INTMASK
class VPIMask : public VPMask {
public:
	VPIMask( int xsize, int ysize );
	VPIMask( int xsize, int ysize, int scale, int offset, 
		std::vector<int> coeff );
	VPIMask( const char * );
	VPIMask( im__INTMASK * );
	VPIMask();
	virtual ~VPIMask();

	VPMask *dup() const;
	void embed( im__INTMASK * );

	int xsize() const;
	int ysize() const;
	int scale() const;
	int offset() const;
	const char *filename() const;

	// Output
	virtual void ostream_print( std::ostream & ) const;

	// Extract start of array of ints
	int *array() const;
};

// Specialise for DOUBLEMASK
class VPDMask : public VPMask {
public:
	VPDMask( int xsize, int ysize );
	VPDMask( int xsize, int ysize, 
		double scale, double offset, std::vector<double> coeff );
	VPDMask( const char * );
	VPDMask( im__DOUBLEMASK * );
	VPDMask();
	virtual ~VPDMask();

	VPMask *dup() const;
	void embed( im__DOUBLEMASK * );

	int xsize() const;
	int ysize() const;
	double scale() const;
	double offset() const;
	const char *filename() const;

	// Output
	virtual void ostream_print( std::ostream & ) const;

	// Extract start of array of doubles
	double *array() const;
};

} // end of namespace _private_detail

inline std::ostream &operator<<( std::ostream &file, 
	const _private_detail::VPMask &msk )
{ 
	msk.ostream_print( file ); 
	return( file ); 
}

#endif /*!SWIG*/

// Wrapper over VP?Mask with ref counting
class VMask {
protected:
	struct refblock {
		_private_detail::VPMask *pmask;	// Mask: double or int
		int nrefs;		// Refs to us

		refblock() : pmask(0), nrefs(1) {}
		virtual ~refblock() { delete pmask; }
	};

	refblock *ref;

	// Make sure this is a private copy of pmask --- dup if nrefs != 1
	void make_private();

public:
	// Constructor leaves msk uninitialised
	VMask() { ref = new refblock; }

	// Copy constructor 
	VMask( const VMask &a ) { ref = a.ref; ref->nrefs++; }

	// Assignment
	VMask &operator=( const VMask &a );

	// Destructor
	virtual ~VMask();

	int xsize() const
		{ return( ref->pmask->xsize() ); }
	int ysize() const
		{ return( ref->pmask->ysize() ); }
	int size() const
		{ return( xsize() * ysize() ); }
	const char *filename() const
		{ return( ref->pmask->filename() ); }

	// Extract underlying type
	_private_detail::VPMask::VMaskType type() const 
		{ return( ref->pmask->type ); }

	// Extract underlying VIPS pointer
	_private_detail::MASKUNION mask() const { return( ref->pmask->data ); }

	void ostream_print( std::ostream & ) const;
};

inline std::ostream &operator<<( std::ostream &file, const VMask &msk )
{
	msk.ostream_print( file );
	return( file );
}

// Need to forward ref these
class VDMask;
class VImage;

// Wrapper over _private_detail::VPIMask with ref counting
class VIMask : public VMask {
public:
	VIMask( int xsize, int ysize )
	{
		ref->pmask = new _private_detail::VPIMask( xsize, ysize );
	}

/* Don't wrap the varargs constructor. We want Python to use the vector one.
 */
#ifndef SWIG
	VIMask( int xsize, int ysize, int scale, int offset, ... )
	{
		va_list ap;
		int i;
		std::vector<int> coeff( xsize * ysize );

		va_start( ap, offset );
		for( i = 0; i < xsize * ysize; i++ )
			coeff[i] = va_arg( ap, int );
		va_end( ap );

		ref->pmask = new _private_detail::VPIMask( xsize, ysize, 
			scale, offset, coeff );
	}
#endif /*!SWIG*/

	VIMask( int xsize, int ysize, int scale, int offset, 
		std::vector<int> coeff )
	{
		ref->pmask = new _private_detail::VPIMask( xsize, ysize, 
			scale, offset, coeff );
	}

	VIMask( const char *name )
	{
		ref->pmask = new _private_detail::VPIMask( name );
	}

	// No mask there yet
	VIMask() {}

	int scale() 
	{ 
		return( ((_private_detail::VPIMask *)ref->pmask)->scale() ); 
	}
	
	int offset() 
	{ 
		return( ((_private_detail::VPIMask *)ref->pmask)->offset() ); 
	}

	// Embed INTMASK in VIMask
	void embed( im__INTMASK * );

	// Overload [] to get linear array subscript.
	int &operator[]( int );

	// Overload () to get matrix subscript.
	int &operator()( int x, int y ) { return( (*this)[x + y*xsize()] ); }

	// and as a function call that SWIG can wrap
	int get( int i )
		{ return( (*this)[i] ); }

	// Type conversion: INTMASK->DOUBLEMASK
	operator VDMask();

	// Type conversion: INTMASK->image
	operator VImage();

	// VIMask build functions
	static VIMask gauss( double, double );
	static VIMask gauss_sep( double, double );
	static VIMask log( double, double );

	// VIMask manipulation
	VIMask rotate45();
	VIMask rotate90();

	// Arithmetic ... cast to double, and use VDMask funcs. For some
	// reason, the compiler won't let us do casts to VDImage yet, so no
	// inlines.
	VDMask trn();
	VDMask inv();
	VDMask cat( VDMask );
	VDMask mul( VDMask );
};

// Wrapper over _private_detail::VPDMask with ref counting
class VDMask : public VMask {
public:
	VDMask( int xsize, int ysize )
	{
		ref->pmask = new _private_detail::VPDMask( xsize, ysize );
	}

/* Don't wrap the varargs constructor. We want Python to use the vector one.
 */
#ifndef SWIG
	VDMask( int xsize, int ysize, double scale, double offset, ... )
	{
		va_list ap;
		int i;
		std::vector<double> coeff( xsize * ysize );

		va_start( ap, offset );
		for( i = 0; i < xsize * ysize; i++ )
			coeff[i] = va_arg( ap, double );
		va_end( ap );

		ref->pmask = new _private_detail::VPDMask( xsize, ysize, 
			scale, offset, coeff );
	}
#endif /*!SWIG*/

	VDMask( int xsize, int ysize, double scale, double offset, 
		std::vector<double> coeff )
	{
		ref->pmask = new _private_detail::VPDMask( xsize, ysize, 
			scale, offset, coeff );
	}

	VDMask( const char *name )
	{
		ref->pmask = new _private_detail::VPDMask( name );
	}

	// No mask yet
	VDMask() { }

	// Embed DOUBLEMASK in VDMask
	void embed( im__DOUBLEMASK * );

	double scale()
	{ 
		return( ((_private_detail::VPDMask *)ref->pmask)->scale() ); 
	}

	double offset()
	{ 
		return( ((_private_detail::VPDMask *)ref->pmask)->offset() ); 
	}

	// Overload [] to get linear array subscript.
	double &operator[]( int );

	// Overload () to get matrix subscript.
	double &operator()( int x, int y )
		{ return( (*this)[x + y*xsize()] ); }

	// and as a function call that SWIG can wrap
	double get( int i ) { return( (*this)[i] ); }

	// Type conversion: double->int
	operator VIMask();

	// Type conversion: DOUBLEMASK->image
	operator VImage();

	// VDMask build functions
	static VDMask gauss( double, double );
	static VDMask log( double, double );

	// VDMask manipulation
	VDMask rotate45();
	VDMask rotate90();

	// Scale to intmask
	VIMask scalei();

	// Simple arithmetic
	VDMask trn();
	VDMask inv();
	VDMask cat( VDMask );
	VDMask mul( VDMask );
};

VIPS_NAMESPACE_END

#endif /*IM_VMASK_H*/
