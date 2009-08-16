/* SWIG interface file for VError.
 */

%module VError
%{
#include <vipsCC/vipscpp.h>
%}

%include "std_except.i"
%include "std_string.i"

%include vipsCC/VError.h

%extend vips::VError {
        const char *__str__ () {
                return $self->what ();
        }
}

