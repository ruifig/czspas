GENERAL
-------

* X Rename project to spas (instead of czspas)
	* X cmake changes done
	* X Rename macros from CZSPAS to SPAS
	* X rename folder(s)
	* X rename bitbucket repo
* X Remove old files
* X Create a LICENSE file (MIT probably)
* X Port to Linux
* X Rename back to czspas (A couple of project on GitHub names spas) ;(
		* X cmake changes
		* X rename macros
		* X rename folder
		* X rename bitbucket repo
* X Organize the header top
	* X Put a copyright notice and link to spas repository
	* X Organize the links and add notes on each
* Create readme.md
* Move to github

API
---

* Make Service::run thread safe, so multiple threads can dequeue work (like Asio)

INTERNALS
---------

* Reactor:
	* When creating the signalIn/Out, have some data exchanged (maybe a guid), to make sure we are accepting the right socket. Any connection attempts that don't send the right data will be dropped.
	* X When creating the temporary listen socket, bind to "127.0.0.1", instead of "0.0.0.0". I believe that binding it to "0.0.0.0" will cause it to accept connections from any origin.
		* HOW: I now listenEx that accepts all parameters, and listen for the common case
	* X When closing the the temporary acceptor, disable lingering? (Need to check if it's necessary)
	* X When closing the 2 temporary sockets, shutdown 1 properly and disable the lingering on the other one, to avoid the TIME_WAIT

