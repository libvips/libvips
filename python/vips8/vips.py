#!/usr/bin/python

import logging
import sys

from gi.repository import GLib
from gi.repository import GObject

# you might need this in your .bashrc
# export GI_TYPELIB_PATH=$VIPSHOME/lib/girepository-1.0
from gi.repository import Vips

class Error(Exception):

    """An error from vips.

    message -- a high-level description of the error
    detail -- a string with some detailed diagnostics
    """

    def __init__(self, message, detail = None):
        self.message = message
        if detail == None:
            detail = Vips.error_buffer()
            Vips.error_clear()
        self.detail = detail

        logging.debug('vips: Error %s %s', self.message, self.detail)

    def __str__(self):
        return '%s %s' % (self.message, self.detail)

class Argument:
    def __init__(self, op, prop):
        self.op = op;
        self.prop = prop;
        self.name = prop.name;
        self.flags = op.get_argument_flags(self.name)
        self.priority = op.get_argument_priority(self.name)
        self.isset = op.argument_isset(self.name)

def _call_base(name, self, required, optional):
    logging.debug('_call_base name=%s, self=%s, required=%s optional=%s' % 
                  (name, self, required, optional))

    try:
        op = Vips.Operation.new(name)
    except TypeError, e:
        raise Error('No such operator.')

    # find all the args for this op, sort into priority order
    args = [Argument(op, x) for x in op.props]
    args.sort(lambda a, b: a.priority - b.priority)

    enm = Vips.ArgumentFlags

    # find all required, unassigned input args
    required_input = [x for x in args if x.flags & enm.INPUT and 
                      x.flags & enm.REQUIRED and 
                      not x.isset]

    # do we have a non-NULL self pointer? this is used to set the first
    # compatible input arg
    if self != None:
        found = False
        for x in required_input:
            if GObject.type_is_a(self, x.prop.value_type):
                op.props.__setattr__(x.name, self)
                required_input.remove(x)
                found = True
                break

        if not found:
            raise Error('Bad arguments.', 'No %s argument to %s.' %
                        (str(self.__class__), name))

    if len(required_input) != len(required):
        raise Error('Wrong number of arguments.', 
                    '"%s" needs %d arguments, you supplied %d' % 
                    (name, len(required_input), len(required)))

    for i in range(len(required_input)):
        logging.debug('assigning %s to %s' % (required[i],
                                               required_input[i].name))
        logging.debug('%s needs a %s' % (required_input[i].name,
                                         required_input[i].prop.value_type))
        op.props.__setattr__(required_input[i].name, required[i])

    # find all optional, unassigned input args ... just need the names
    optional_input = [x.name for x in args if x.flags & enm.INPUT and 
                      not x.flags & enm.REQUIRED and 
                      not x.isset]

    for key in optional.keys():
            if not key in optional_input:
                raise Error('Unknown argument.', 
                            'Operator %s has no argument %s' % (name, key))

    # set optional input args
    for key in optional.keys():
        op.props.__setattr__(key, optional[key])

    # call
    op2 = Vips.cache_operation_build(op)
    if op2 == None:
        raise Error('Error calling operator %s.' % name)

    # find all required output args ... just need the names
    # we can't check assigned here (since we captured the value before the call)
    # but the getattr will test that for us anyway
    required_output = [x.name for x in args if x.flags & enm.OUTPUT and 
                       x.flags & enm.REQUIRED]

    # gather output args 
    out = []
    for x in required_output:
        out.append(op2.props.__getattribute__(x))

    # find all optional output args ... just need the names
    optional_output = [x.name for x in args if x.flags & enm.OUTPUT and 
                       not x.flags & enm.REQUIRED]

    for x in optional.keys():
        if x in optional_output:
            out.append(op2.props.__getattribute__(x))

    if len(out) == 1:
        out = out[0]

    # unref everything now we have refs to all outputs we want
    op2.unref_outputs()

    return out

# general user entrypoint 
def call(name, *args, **kwargs):
    return _call_base(name, None, args, kwargs)

# from getattr ... try to run the attr as a method
def _call_instance(self, name, args, kwargs):
    return _call_base(name, self, args, kwargs)

class Image(Vips.Image):
    def __init__(self, filename = None, mode = None):
        Vips.Image.__init__(self)

        if filename:
            self.props.filename = filename
            if not mode:
                mode = "rd"
        if mode:
            self.props.mode = mode

        if self.build() != 0:
            print 'build failed'
            raise Error('Unable to build image')

    def __getattr__(self, name):
        logging.debug('vipsimage: __getattr__ %s' % name)
        return lambda *args, **kwargs: _call_instance(self, name, args, kwargs)

# start up vips!
Vips.init(sys.argv[0])

