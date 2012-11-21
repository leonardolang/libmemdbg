# libmemdbg - concurrent memory debugging library

## Description and motivation

This is a memory debugging library - similar to DUMA and others that replace
or insert hooks on malloc() et al - but with a very specific focus: provide
high performance during very concurrent memory allocations with dynamic thread
creation and destruction (ie, hundreds to thousands of threads per second).

It was written during last quarter of 2012, to debug a very hard-to-reproduce
memory corruption in a process with thousands of concurrent threads, where
each was doing hundreds of memory allocations and deallocations per second
and threads were also created/destroyed very quickly.

Most libraries at the time either had poor perfomance and/or did not work well
with the specific software/scenario. By being a minimal library (around ~670
SLOC of C++ code), this code also added little surface area to debug, which
made isolating the problem easier.


## Design, goals and tradeoffs

The library works by memory mapping "areas" of memory, where all memory is
pre-mapped and split into 128 areas of 64MiB each (which can be configured
by C defines).

Each 64MiB is divided in slots of 512-byte each, which is the smallest unit
the allocator can handle. It creates more waste if the process does very
small allocations, but at the same time it simplifies greatly the management
of the memory.

These areas are split by running threads, where `tid mod number-of-areas`
is used for selecting the default area where the thread allocates. If the
thread exhausts the area it will try to allocate from the next one, repeating
the process sequentially, until some available space is found, or a NULL
pointer (OOM condition) is returned.

The per-area allocator is a mix of region-based allocator with "free lists",
and begins allocation by simply incrementing a "current" pointer when memory
is requested. After all area has been used, it reverts to scanning free slots
and recycling them.

The allocation attempts to use as much address space as possible for reducing
the reuse of the same addresses and thus increasing the chances of detecting
incorrect access of an old (freed) memory allocation.


## Performance and memory usage

Using the default settings, a process that uses ~1GiB of memory can quickly
reach 2-3GiB depending on the amount of waste, and will keep using 8GiB of
virtual space as long as it is running.

Concurrency may improve if the number of areas is increased, but a large number
of regions can also lead to more threads having to loop over multiple areas,
thus defeating the purpose of separate memory regions.

Numbers between 64-512 have been tried for the tested environment, and the
best performance was achieved with 128 areas (current default).


## Final considerations

Modern libraries for debugging and tracing memory allocation (like tcmalloc)
should be more performant and are definitely more powerful than this, but
this code may still be useful if something simpler is desired - and can be
quickly hacked/optimized for other needs.
