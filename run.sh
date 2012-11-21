#!/bin/sh
set -x
exec env LD_PRELOAD=$(pwd)/libmemdbg.so "$@"