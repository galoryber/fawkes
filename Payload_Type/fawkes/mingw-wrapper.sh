#!/bin/bash
# Wrapper for x86_64-w64-mingw32-gcc that fixes intermittent corrupt export_file.def.
#
# Go's linker for -buildmode=c-shared occasionally writes a corrupt export_file.def
# (the file that lists DLL exports for mingw's linker). When this happens, mingw
# reports "syntax error" / "file format not recognized" and the build fails.
#
# This wrapper intercepts the gcc invocation, checks if any export_file.def argument
# is corrupt, and replaces it with the correct content from /tmp/fawkes_exports.def
# (written by the builder before compilation starts).

for arg in "$@"; do
    if [[ "$arg" == */export_file.def ]]; then
        if [ -f "$arg" ]; then
            first_line=$(head -1 "$arg" 2>/dev/null)
            if [[ "$first_line" != EXPORTS* ]]; then
                if [ -f /tmp/fawkes_exports.def ]; then
                    cp /tmp/fawkes_exports.def "$arg"
                fi
            fi
        fi
    fi
done
exec /usr/bin/x86_64-w64-mingw32-gcc "$@"
