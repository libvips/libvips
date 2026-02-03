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
#include <stdexcept>

#include <vips/vips.h>

VIPS_NAMESPACE_START

/**
 * The libvips error class. It holds a single string containing an
 * internationalized error message in utf-8 encoding.
 */
class VIPS_CPLUSPLUS_API VError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;

	/**
	 * Construct a VError, fetching the error message from the libvips
	 * error buffer.
	 */
	VError() : std::runtime_error(vips_error_buffer()) {}

	/**
	 * Get a reference to the underlying C string.
	 * Note: this override must be preserved for ABI, removing it
	 * would also eliminate the `_ZNK4vips6VError4whatEv` symbol.
	 */
	const char *
	what() const noexcept override
	{
		return std::runtime_error::what();
	}

	/**
	 * Print the error message to a stream.
	 */
	void ostream_print(std::ostream &) const;

private:
	/**
	 * ABI padding to preserve original VError size.
	 */
	// TODO: Migrate to [[maybe_unused]] once we require C++17.
	char _abi_padding[sizeof(std::exception) + sizeof(std::string) -
		sizeof(std::runtime_error)] G_GNUC_UNUSED = {};
};

VIPS_NAMESPACE_END

#endif /*VIPS_VERROR_H*/
