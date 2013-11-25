#!/usr/bin/python

import re
import math
import cairo

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

class Thread:
    thread_number = 0

    def __init__(self, thread_name):
        self.thread_name = thread_name
        self.thread_number = Thread.thread_number
        self.events = []
        Thread.thread_number += 1

class Event:
    def __init__(self, thread, gate_name, start, stop):
        self.thread = thread
        self.gate_name = gate_name
        self.start = start
        self.stop = stop

        self.work = False
        self.wait = False
        if re.match('.*: .*work.*', gate_name):
            self.work = True
        if re.match('.*: .*wait.*', gate_name):
            self.wait = True

        thread.events.append(self)

thread_id = 0
threads = []
n_events = 0
with ReadFile('vips-profile.txt') as rf:
    while rf:
        match = re.match('thread: (.*)', rf.line)
        if not match:
            print 'parse error line %d, expected "thread"' % rf.lineno
        thread_name = match.group(1) + " " + str(thread_id)
        thread_id += 1
        thread = Thread(thread_name)
        threads.append(thread)
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
                Event(thread, gate_name, a, b)
                n_events += 1

for thread in threads:
    thread.events.sort(lambda x, y: cmp(x.start, y.start))

print 'loaded %d events' % n_events

# normalise time axis to secs of computation
ticks_per_sec = 1000000.0
start_time = threads[0].events[0].start
last_time = 0
for thread in threads:
    for event in thread.events:
        event.start = (event.start - start_time) / ticks_per_sec
        event.stop = (event.stop - start_time) / ticks_per_sec

        if event.stop > last_time:
            last_time = event.stop

print 'last time =', last_time

# do two gates overlap?
def is_overlap(events, gate_name1, gate_name2):
    for event1 in events:
        if event1.gate_name != gate_name1:
            continue

        for event2 in events:
            if event2.gate_name != gate_name2:
                continue

            # if either endpoint of 1 is within 2
            if event1.start > event2.start and event1.stop < event2.stop:
                return True
            if event1.stop > event2.start and event1.stop < event2.stop:
                return True

    return False

# allocate a y position for each gate
total_y = 0
for thread in threads:
    y = 1
    gate_positions = {}
    for event in thread.events:
        if event.work or event.wait:
            gate_positions[event.gate_name] = 0
        elif not event.gate_name in gate_positions:
            overlap = True
            for gate_name in gate_positions:
                if not is_overlap(thread.events, gate_name, event.gate_name):
                    gate_positions[event.gate_name] = gate_positions[gate_name]
                    overlap = False
                    break

            if overlap:
                gate_positions[event.gate_name] = y
                y += 1

        event.y = gate_positions[event.gate_name]
        event.total_y = total_y + y

    total_y += y

PIXELS_PER_SECOND = 1000
PIXELS_PER_GATE = 20
WIDTH = int(last_time * PIXELS_PER_SECOND)
HEIGHT = int(total_y * PIXELS_PER_GATE)

surface = cairo.ImageSurface (cairo.FORMAT_ARGB32, WIDTH, HEIGHT)
ctx = cairo.Context (surface)

ctx.scale (PIXELS_PER_SECOND, PIXELS_PER_GATE) 

for thread in threads:
    for event in thread.events:
        ctx.move_to (event.start, event.total_y)
        ctx.line_to (event.stop, event.total_y)
        ctx.close_path ()
        ctx.set_line_width (0.5)

        if event.wait:
            ctx.set_source_rgb (0.9, 0.1, 0.1)
        elif event.work:
            ctx.set_source_rgb (0.1, 0.9, 0.1)
        else:
            ctx.set_source_rgb (0.1, 0.1, 0.9)

        ctx.stroke ()

surface.write_to_png ("example.png") # Output to PNG
