#!/bin/sh
# Copyright (C) The c-ci project and its contributors
# SPDX-License-Identifier: MIT
set -e
# Check that all of the base fuzzing corpus parse without errors
./cifuzz fuzzinput/*
./cifuzzname fuzznames/*
