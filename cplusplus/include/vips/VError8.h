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
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifndef VIPS_VERROR_H
#define VIPS_VERROR_H

#include <cstring>
#include <ostream>
#include <exception>

#include <vips/vips.h>

VIPS_NAMESPACE_START

/**
 * The libvips error class. It holds a single string containing an
 * internationalized error message in utf-8 encoding.
 */
class VIPS_CPLUSPLUS_API VError : public std::exception {
	std::string _what;

public:
	/**
	 * Construct a VError, setting the error message.
	 */
	VError(const std::string &what) : _what(what) {}

	/**
	 * Construct a VError, fetching the error message from the libvips
	 * error buffer.
	 */
	VError() : _what(vips_error_buffer()) {}

	virtual ~VError() throw() {}

	/**
	 * Get a reference to the underlying C string.
	 */
	virtual const char *
	what() const throw()
	{
		return _what.c_str();
	}

	/**
	 * Print the error message to a stream.
	 */
	void ostream_print(std::ostream &) const;
};

VIPS_NAMESPACE_END

#endif /*VIPS_VERROR_H*/
