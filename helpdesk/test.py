#!/usr/bin/env python
# This file is used for testing edits to the bash function.
# It echoes back the arguments that are passed.
import sys

print("Test file successfully called with args:")

for arg in sys.argv[1:]:
    print(arg)
