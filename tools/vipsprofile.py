#!/usr/bin/python

import re
import math
import cairo

class ReadFile:
    def __init__(self, filename):
        self.filename = filename

    def __enter__(self):
        self.f = open(self.filename, 'r') 
        self.lineno = 0
        self.getnext();
        return self

    def __exit__(self, type, value, traceback):
        self.f.close()

    def __nonzero__(self):
        return self.line != ""

    def getnext(self):
        self.lineno += 1
        self.line = self.f.readline()

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
        if re.match('.*?: .*work.*', gate_name):
            self.work = True
        if re.match('.*?: .*wait.*', gate_name):
            self.wait = True

        thread.events.append(self)

input_filename = 'vips-profile.txt'

thread_id = 0
threads = []
n_events = 0
print 'reading from', input_filename
with ReadFile(input_filename) as rf:
    while rf:
        if rf.line.rstrip() == "":
            rf.getnext()
            continue
        if rf.line[0] == "#":
            rf.getnext()
            continue

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
            match = re.match('vips_(.*)', gate_name)
            if match:
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
    thread.total_y = total_y

    y = 1
    gate_positions = {}
    for event in thread.events:
        if event.work or event.wait:
            gate_positions[event.gate_name] = 0
        elif not event.gate_name in gate_positions:
            no_overlap = False
            for gate_name in gate_positions:
                if not is_overlap(thread.events, gate_name, event.gate_name):
                    gate_positions[event.gate_name] = gate_positions[gate_name]
                    no_overlap = True
                    break

            if not no_overlap:
                gate_positions[event.gate_name] = y
                y += 1

        event.y = gate_positions[event.gate_name]
        event.total_y = total_y + event.y

    total_y += y

PIXELS_PER_SECOND = 1000
PIXELS_PER_GATE = 20
LEFT_BORDER = 320
BAR_HEIGHT = 5
WIDTH = int(LEFT_BORDER + last_time * PIXELS_PER_SECOND)
HEIGHT = int((total_y + 1) * PIXELS_PER_GATE)

surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, WIDTH + 50, HEIGHT)
ctx = cairo.Context(surface)
ctx.select_font_face('Sans')
ctx.set_font_size(15)

def draw_event(ctx, event):
    left = event.start * PIXELS_PER_SECOND + LEFT_BORDER
    top = event.total_y * PIXELS_PER_GATE 
    width = (event.stop - event.start) * PIXELS_PER_SECOND - 1
    height = BAR_HEIGHT

    ctx.rectangle(left, top, width, height)

    if event.wait:
        ctx.set_source_rgb(0.9, 0.1, 0.1)
    elif event.work:
        ctx.set_source_rgb(0.1, 0.9, 0.1)
    else:
        ctx.set_source_rgb(0.1, 0.1, 0.9)

    ctx.fill()

    if not event.wait and not event.work:
        xbearing, ybearing, twidth, theight, xadvance, yadvance = \
                ctx.text_extents(event.gate_name)

        ctx.move_to(left + width / 2 - twidth / 2, top + theight)
        ctx.set_source_rgb(1.00, 0.83, 0.00)
        ctx.show_text(event.gate_name)
        #ctx.stroke()

for thread in threads:
    xbearing, ybearing, twidth, theight, xadvance, yadvance = \
            ctx.text_extents(thread.thread_name)
    ctx.move_to(0, theight + thread.total_y * PIXELS_PER_GATE)
    ctx.set_source_rgb(1.00, 1.00, 1.00)
    ctx.show_text(thread.thread_name)
    #ctx.stroke()

    for event in thread.events:
        draw_event(ctx, event)

output_filename = "example.png"
print 'writing to', output_filename
surface.write_to_png(output_filename) 
