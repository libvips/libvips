#!/usr/bin/env python

import sys
sys.path.append('../python/packages')

import unittest

from test_arithmetic import *
from test_colour import *
from test_conversion import *
from test_convolution import *
from test_create import *
from test_draw import *
from test_foreign import *
from test_histogram import *
from test_morphology import *
from test_resample import *
from test_iofuncs import *

if __name__ == '__main__':
    unittest.main()

