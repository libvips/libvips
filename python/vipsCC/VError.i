/* SWIG interface file for VError.
 */

%module VError
%{
#include <vips/vipscpp.h>
%}

%include "std_except.i"
%include "std_string.i"

%include vips/VError.h

%extend vips::VError {
        const char *__str__ () {
                return $self->what ();
        }
}

