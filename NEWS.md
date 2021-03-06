openCAPWAP
==========

A Open Source implementation of CAPWAP

Home: [http://github.com/travelping/openCAPWAP](http://github.com/travelping/openCAPWAP)

Changes with 1.2.1 - 07 Jan 2014
--------------------------------

* allow the new parent in ralloc_steal to be NULL to detach a pointer
  from it's parent
* Data Channel KeepAlive messages are now RFC compliant, invalid formated
  messages will be logged, but accepted for backwards compatibility
* allow certificate chains with a length three (one sub-CA)

Changes with 1.2.0 - 18 Sep 2013
--------------------------------

* switch memory allocation to context based ralloc (recusive malloc)
  and clean object memory management a lot
* rework capwap decoder and encoder to work in place instead of copying
  around gazillion small fragments
* reduce pthread stack sizes
* fix all compiler warnings, it now compiles with -Werror
* add support for aggressive data channel keep-alive till run state is
  confirmed
* convert most function like macros to proper `do {} while(0)` blocks
  and compound statements
