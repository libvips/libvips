#!/usr/bin/python

import weakref

class Finalizable(object):
    """
    Base class enabling the use a __finalize__ method without all the
    problems associated with __del__ and reference cycles.

    If you call enable_finalizer(), it will call __finalize__
    with a single "ghost instance" argument after the object has been
    deleted. Creation of this "ghost instance" does not involve calling
    the __init__ method, but merely copying the attributes whose names
    were given as arguments to enable_finalizer().

    A Finalizable can be part of any reference cycle, but you must be careful
    that the attributes given to enable_finalizer() don't reference back to
    self, otherwise self will be immortal.
    """

    __wr_map = {}
    __wr_id = None

    def bind_finalizer(self, *attrs):
        """
        Enable __finalize__ on the current instance.
        The __finalize__ method will be called with a "ghost instance" as
        single argument.
        This ghost instance is constructed from the attributes whose names
        are given to bind_finalizer(), *at the time bind_finalizer() is called*.
        """
        cls = type(self)
        ghost = object.__new__(cls)
        ghost.__dict__.update((k, getattr(self, k)) for k in attrs)
        cls_wr_map = cls.__wr_map
        def _finalize(ref):
            try:
                ghost.__finalize__()
            finally:
                del cls_wr_map[id_ref]
        ref = weakref.ref(self, _finalize)
        id_ref = id(ref)
        cls_wr_map[id_ref] = ref
        self.__wr_id = id_ref

    def remove_finalizer(self):
        """
        Disable __finalize__, provided it has been enabled.
        """
        if self.__wr_id:
            cls = type(self)
            cls_wr_map = cls.__wr_map
            del cls_wr_map[self.__wr_id]
            del self.__wr_id


class TransactionBase(Finalizable):
    """
    A convenience base class to write transaction-like objects,
    with automatic rollback() on object destruction if required.
    """

    finished = False

    def enable_auto_rollback(self):
        self.bind_finalizer(*self.ghost_attributes)

    def commit(self):
        assert not self.finished
        self.remove_finalizer()
        self.do_commit()
        self.finished = True

    def rollback(self):
        assert not self.finished
        self.remove_finalizer()
        self.do_rollback(auto=False)
        self.finished = True

    def __finalize__(ghost):
        ghost.do_rollback(auto=True)


class TransactionExample(TransactionBase):
    """
    A transaction example which close()s a resource on rollback
    """
    ghost_attributes = ('resource', )

    def __init__(self, resource):
        self.resource = resource
        self.enable_auto_rollback()

    def __str__(self):
        return "ghost-or-object %s" % object.__str__(self)

    def do_commit(self):
        pass

    def do_rollback(self, auto):
        if auto:
            print "auto rollback", self
        else:
            print "manual rollback", self
        self.resource.close()
