GENERAL
-------

API
---

* Revise the timeoutMs parameters.
	* Some methods/functions probably don't need a timeout parameter
* Allow move-semantics for all the objects (Service, Acceptor, Socket)

Unit Tests
----------

* Remove all timer objects from the tests, except for gTimer
* Create unit tests for:
	* Service::stop
	* Service::isStopped
	* Service::reset

INTERNALS
---------


