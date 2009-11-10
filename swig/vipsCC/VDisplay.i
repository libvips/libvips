/* SWIG interface file for VDisplay.
 */

%module VDisplay
%{
#include <vips/vipscpp.h>
%}

%import "VError.i"

/* Need to override assignment to get refcounting working.
 */
%rename(__assign__) *::operator=;

%include vips/VDisplay.h
