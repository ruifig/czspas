GENERAL
-------

* Cleanup the utils.cmake
	* Change the utility functions/macros to take an explicity target name
	* X : Remove "project(xx)" from the top of cmake files

API
---

* Make Service::run thread safe, so multiple threads can dequeue work (like Asio)

INTERNALS
---------

* Reactor:
	* When creating the signalIn/Out, have some data exchanged (maybe a guid), to make sure we are accepting the right socket. Any connection attempts that don't send the right data will be dropped.

