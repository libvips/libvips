/* SWIG interface file for VMask.
 */

%module VMask
%{
#include <stdexcept>
#include <vipsCC/vipscpp.h>
%}

%import "VError.i"
%import "VImage.i"

/* Need to override assignment to get refcounting working.
 */
%rename(__assign__) *::operator=;

/* [] is array subscript, as you'd expect.
 */
%rename(__index__) vips::VIMask::operator[];
%rename(__index__) vips::VDMask::operator[];

/* () is 2d array subscript, how odd!
 */
%rename(__call__) vips::VIMask::operator();
%rename(__call__) vips::VDMask::operator();

/* Type conversion operators renamed as functions.
 */
%rename(convert_VImage) vips::VIMask::operator vips::VImage;
%rename(convert_VImage) vips::VDMask::operator vips::VImage;

%rename(convert_VIMask) vips::VDMask::operator vips::VIMask;
%rename(convert_VDMask) vips::VIMask::operator vips::VDMask;

%include vipsCC/VMask.h
