GENERAL
-------

* Rename project to spas (instead of czspas)
	* X cmake changes done
	* X Rename macros from CZSPAS to SPAS
	* rename folder(s)
	* rename bitbucket repo
* Move to github
* X Remove old files
* Organize the header top
	* Put a copyright notice and link to spas repository
	* Organize the links and add notes on each
* X Create a LICENSE file (MIT probably)
* Port to Linux


API
---

* Make Service::run thread safe, so multiple threads can dequeue work (like Asio)


INTERNALS
---------

* Reactor:
	* When creating the signalIn/Out, have some data exchanged (maybe a guid), to make sure we are accepting the right socket. Any connection attempts that don't send the right data will be dropped.
	* DONE - When creating the temporary listen socket, bind to "127.0.0.1", instead of "0.0.0.0". I believe that binding it to "0.0.0.0" will cause it to accept connections from any origin.
		* HOW: I now listenEx that accepts all parameters, and listen for the common case
	* DONE - When closing the the temporary acceptor, disable lingering? (Need to check if it's necessary)
	* DONE - When closing the 2 temporary sockets, shutdown 1 properly and disable the lingering on the other one, to avoid the TIME_WAIT

OLD STUFF / NA
--------------
- Port to Linux showed a couple of problems
	- There is a race condition related with a call to cancel and and IODemux, showing up mostly on the Acceptor. Example:
		1 - When the IODemux handles an event, it removes that event flag before calling the handler. If all flags are removed, it removes the socket from the set.
		2 - When the IODemux handles a cancel, it might then not find the socket to cancel.
		3 - This can cause the chain of operations to break for a socket, since the cancel fails internally, but the operation queued by IODemux at 1) is ready for execution as sucessfull.
		- In this means the socket will never detect the cancel

		The way to fix this should be to have the IODemux socket set have always all the sockets, and do:
			- cancel and handling events still reset the flags. This means no further events will be signaled for the socket unless it registers itself for further events

	- Leaving uncalled handlers in the IOService can cause all sorts of problems, such as Acceptors not being destroyed (and as such keeping further Acceptors from using that port). This is because the Acceptor/Socket keeps the user handler std::function as part of itself. Example:
		- We register an asyncAccept (passing a std::shared_ptr to the Acceptor itself). This gets saved in the Acceptor itself.
		- The Service gets destroyed, and the pending operations are deleted without calling the handlers. This means the data in Accecptor is not reset (the m_acceptInfo), and thus the std::shared_ptr is not deleted. This causes the Acceptor to never be destroyed.
		- The way to fix this is to have the user handler information move around with the internal handlers. This means any objects captured as part of the user handlers will be destroyed even if the handlers were not called.


