#!/usr/bin/env bash
cd "/home/vboxuser/Downloads/syscall_trace_improved(1)/syscall_trace_improved"

make clean && make

echo
echo "Build completed."
echo "Starting syscall tracer..."
echo

pkexec ./syscall_trace
status=$?

echo
echo "TRACER EXIT CODE: $status"
echo
exec bash

echo
read -n 1 -s -r -p "Press any key to close..."
echo