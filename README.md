autopin
=======

This is the original autopin implementation. Feel free to try it, but it may be outdated. Try [Autopin+](https://github.com/autopin/autopin-plus) for a current tool.

Autopin is a thread to core pinning tool, based on perfmon. To use this tool, the perfmon patch must be installed. Furthermore for NUMA-architectures the automatic page migration patch by Lee Schermerhorn must be installed ([Patch](http://free.linux.hp.com/~lts/Patches/PageMigration/2.6.36-mmotm-101103-1217/)). Autopin is designed to work with the Intel compiler.

Howto:
------

1. make in the autopin folder 

2. start autopin: OMP_NUM_THREADS=4 SCHEDULE=0123,0246,4561,3254 autopin/autopin --follow-all --init-time 5 -t 1 -w 5 -e INSTRUCTIONS_RETIRED testprog/exampleprogram 
