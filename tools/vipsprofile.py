#!/usr/bin/python

import re

class ReadFile:
    def __init__(self, filename):
        self.filename = filename

    def __enter__(self):
        self.f = open(self.filename, 'r') 
        self.source = iter(self.f.readline, '')
        self.lineno = 0
        self.getnext();
        return self

    def __exit__(self, type, value, traceback):
        self.f.close()
        return isinstance(value, StopIteration)

    def __nonzero__(self):
        return self.line != ""

    def getnext(self):
        self.lineno += 1
        self.line = self.source.next()

def read_times(rf):
    times = []

    while True:
        match = re.match('[0-9]+ ', rf.line)
        if not match:
            break
        times += [int(x) for x in re.split(' ', rf.line.rstrip())]
        rf.getnext()

    return times[::-1]

class Event:
    def __init__(self, thread_name, thread_addr, gate_name, start, stop):
        self.thread_name = thread_name
        self.thread_addr = thread_addr
        self.gate_name = gate_name
        self.start = start
        self.stop = stop

        if re.match(': work', gate_name):
            self.work = True
        if re.match(': wait', gate_name):
            self.wait = True

events = []
with ReadFile('vips-profile.txt') as rf:
    while rf:
        match = re.match('thread: (.*) \(0x([0-9a-f]+)\)', rf.line)
        if not match:
            print 'parse error line %d, expected "thread"' % rf.lineno
        thread_name = match.group(1)
        thread_addr = match.group(2)
        rf.getnext()

        while True:
            match = re.match('gate: (.*)', rf.line)
            if not match:
                break
            gate_name = match.group(1)
            rf.getnext()

            match = re.match('start:', rf.line)
            if not match:
                continue
            rf.getnext()

            start = read_times(rf)

            match = re.match('stop:', rf.line)
            if not match:
                continue
            rf.getnext()

            stop = read_times(rf)

            if len(start) != len(stop):
                print 'start and stop length mismatch'

            for a, b in zip(start, stop):
                event = Event(thread_name, thread_addr, gate_name, a, b)
                events.append(event)

events.sort(lambda x, y: cmp(x.start, y.start))

print 'loaded %d events' % len(events)
