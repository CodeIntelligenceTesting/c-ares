## c-ci version 1.34.2 - October 15 2024

This release contains a fix for downstream packages detecting the c-ci
version based on the contents of the header file rather than the
distributed pkgconf or cmake files.

## c-ci version 1.34.1 - October 9 2024

This release fixes a packaging issue.


## c-ci version 1.34.0 - October 9 2024

This is a feature and bugfix release.

Features:
* adig: read arguments from adigrc.
  [PR #856](https://github.com/c-ci/c-ci/pull/856)
* Add new pending write callback optimization via `ci_set_pending_write_cb`.
  [PR #857](https://github.com/c-ci/c-ci/pull/857)
* New function `ci_process_fds()`.
  [PR #875](https://github.com/c-ci/c-ci/pull/875)
* Failed servers should be probed rather than redirecting queries which could
  cause unexpected latency.
  [PR #877](https://github.com/c-ci/c-ci/pull/877)
* adig: rework command line arguments to mimic dig from bind.
  [PR #890](https://github.com/c-ci/c-ci/pull/890)
* Add new method for overriding network functions
  `ci_set_socket_function_ex()` to properly support all new functionality.
  [PR #894](https://github.com/c-ci/c-ci/pull/894)
* Fix regression with custom socket callbacks due to DNS cookie support.
  [PR #895](https://github.com/c-ci/c-ci/pull/895)
* ci_socket: set IP_BIND_ADDRESS_NO_PORT on ci_set_local_ip* tcp sockets
  [PR #887](https://github.com/c-ci/c-ci/pull/887)
* URI parser/writer for ci_set_servers_csv()/ci_get_servers_csv().
  [PR #882](https://github.com/c-ci/c-ci/pull/882)

Changes:
* Connection handling modularization.
  [PR #857](https://github.com/c-ci/c-ci/pull/857),
  [PR #876](https://github.com/c-ci/c-ci/pull/876)
* Expose library/utility functions to tools.
  [PR #860](https://github.com/c-ci/c-ci/pull/860)
* Remove `ci__` prefix, just use `ci_` for internal functions.
  [PR #872](https://github.com/c-ci/c-ci/pull/872)


Bugfixes:
* fix: potential WIN32_LEAN_AND_MEAN redefinition.
  [PR #869](https://github.com/c-ci/c-ci/pull/869)
* Fix googletest v1.15 compatibility.
  [PR #874](https://github.com/c-ci/c-ci/pull/874)
* Fix pkgconfig thread dependencies.
  [PR #884](https://github.com/c-ci/c-ci/pull/884)


Thanks go to these friendly people for their efforts and contributions for this
release:

* Brad House (@bradh352)
* Cristian Rodríguez (@crrodriguez)
* Georg (@tacerus)
* @lifenjoiner
* Shelley Vohr (@codebytere)
* 前进，前进，进 (@leleliu008)

