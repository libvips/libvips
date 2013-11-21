#!/usr/bin/python

import re
import math
import cairo

WIDTH, HEIGHT = 256, 256

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
    def __init__(self, thread_name, gate_name, start, stop):
        self.thread_name = thread_name
        self.gate_name = gate_name
        self.start = start
        self.stop = stop

        if re.match(': work', gate_name):
            self.work = True
        if re.match(': wait', gate_name):
            self.wait = True

events = []
thread_id = 0
with ReadFile('vips-profile.txt') as rf:
    while rf:
        match = re.match('thread: (.*)', rf.line)
        if not match:
            print 'parse error line %d, expected "thread"' % rf.lineno
        thread_name = match.group(1) + " " + str(thread_id)
        thread_id += 1
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
                event = Event(thread_name, gate_name, a, b)
                events.append(event)

events.sort(lambda x, y: cmp(x.start, y.start))

print 'loaded %d events' % len(events)

# normalise time axis to secs of computation
ticks_per_sec = 1000000.0
start_time = events[0].start
for event in events:
    event.start = (event.start - start_time) / ticks_per_sec
    event.stop = (event.stop - start_time) / ticks_per_sec
last_time = events[-1].stop
print 'last time =', last_time

# within each thread, allocate a Y position
threads = []
for event in events:
    if not event.thread_name in threads:
        threads.append(event.thread_name)




surface = cairo.ImageSurface (cairo.FORMAT_ARGB32, WIDTH, HEIGHT)
ctx = cairo.Context (surface)

ctx.scale (WIDTH, HEIGHT) # Normalizing the canvas

pat = cairo.LinearGradient (0.0, 0.0, 0.0, 1.0)
pat.add_color_stop_rgba (1, 0.7, 0, 0, 0.5) # First stop, 50% opacity
pat.add_color_stop_rgba (0, 0.9, 0.7, 0.2, 1) # Last stop, 100% opacity

ctx.rectangle (0, 0, 1, 1) # Rectangle(x0, y0, x1, y1)
ctx.set_source (pat)
ctx.fill ()

ctx.translate (0.1, 0.1) # Changing the current transformation matrix

ctx.move_to (0, 0)
ctx.arc (0.2, 0.1, 0.1, -math.pi/2, 0) # Arc(cx, cy, radius, start_angle, stop_angle)
ctx.line_to (0.5, 0.1) # Line to (x,y)
ctx.curve_to (0.5, 0.2, 0.5, 0.4, 0.2, 0.8) # Curve(x1, y1, x2, y2, x3, y3)
ctx.close_path ()

ctx.set_source_rgb (0.3, 0.2, 0.5) # Solid color
ctx.set_line_width (0.02)
ctx.stroke ()

surface.write_to_png ("example.png") # Output to PNG
