// Header for error type

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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef IM_VERROR_H
#define IM_VERROR_H

/* SWIG includes this file directly rather than going through vipscpp.h ... so
 * we have to define these macros here as well.
 */
#ifdef SWIG
#define VIPS_NAMESPACE_START namespace vips {
#define VIPS_NAMESPACE_END }
#endif /*SWIG*/

/* Don't include these when parsing for SWIG.
 */
#ifndef SWIG
# include <string>
# include <iosfwd>
# include <exception>
#endif /*!SWIG*/

VIPS_NAMESPACE_START

// Error type
class VError : public std::exception {
	std::string _what;

public:
	VError( std::string what ) : _what( what ) {}
	VError() {}
	virtual ~VError() throw() {}

	// Print message and exit
	void perror( const char * );
	void perror();

	// Append some more text to the message
	VError &app( std::string txt );
	VError &app( const int i );

	// Extract string
	virtual const char *what() const throw() { return _what.c_str(); }
	void ostream_print( std::ostream & ) const;
};

inline std::ostream &operator<<( std::ostream &file, const VError &err )
{
	err.ostream_print( file );
	return( file );
}

void verror( std::string str = "" ) throw( VError );

VIPS_NAMESPACE_END

#endif /*IM_VERROR_H*/
