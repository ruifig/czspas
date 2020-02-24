GENERAL
-------

API
---

* Revise the timeoutMs parameters.
	* Some methods/functions probably don't need a timeout parameter
* Allow move-semantics for all the objects (Service, Acceptor, Socket)
* Implement Service::poll, which is similar to Service::run, but doesn't block
	* Initially I had a "bool loop" parameter in Service::run, but it didn't work as expected
	* Probably need to change Reactor::runOnce so it doesn't block. Maybe force a timeout of 0 ?
	* Create unit tests
* Implement Service::dispatch
	* This will require some version of http://www.crazygaze.com/blog/2016/03/11/callstack-markers-boostasiodetailcall_stack/ 
* Implement a Resolver class, to resolve host names

Unit Tests
----------

* Remove all timer objects from the tests, except for gTimer
* Create unit tests for:
	* Service::stop
	* Service::isStopped
	* Service::reset
	* Service::run(false)
	* BaseSocket::setLinger , if I keep that function

INTERNALS
---------

* Remove Socket::_forceClose ???

