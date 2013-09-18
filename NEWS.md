opencapwap - Open Source implementation of CAPWAP
=================================================

Changes with 1.2.0
------------------

* switch memory allocation to context based ralloc (recusive malloc)
  and clean object memory managment a lot
* rework capwap decoder and encoder to work in place instead of copying
  around gazillion small fragments
* reduce pthread stack sizes
* fix all compiler warnings, it now compiles with -Werror
* add support for aggressive data channel keep-alive till run state is
  confirmed
* convert most function like macros to proper ''do {} while(0)'' blocks
  and compound statements
