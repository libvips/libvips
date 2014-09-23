#!/bin/bash

export G_DEBUG=fatal-warnings

while true; do
	if ! python test_colour.py TestColour.test_bug; then
		exit 
	fi
done
