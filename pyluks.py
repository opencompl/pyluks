#!/usr/bin/env python3

import argparse

parser = argparse.ArgumentParser(
    prog = 'PyLuks',
    description = 'Create a Luks filesystem image from python')

args = parser.parse_args()

