certinel [![GoDoc][godoc-badge]][godoc]
=======================================

[![Unsupported](https://img.shields.io/badge/Pantheon-Unsupported-yellow?logo=pantheon&color=FFDC28)](https://pantheon.io/docs/oss-support-levels#unsupported)

> NOTE: This is Pantheon's fork of https://github.com/cloudflare/certinel. It adds additional
> functionality and Pantheon-specific opinions.

[godoc-badge]: https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square
[godoc]: https://godoc.org/github.com/pantheon-systems/certinel

Certinel is a Go library that makes it even easier to implement zero-hit
TLS certificate changes by watching for certificate changes for you. The
methods required by `tls.Config` are already implemented for you.

There are two watcher implementations available:

- [pollwatcher](./pollwatcher): Uses the stat() systemcall to check for an updated certificate
  on a configurable intervable. Common intervals are 1-5 minutes.
- [fswatcher](./fswatcher): Uses the [fsnotify][fsnotify] library for immediate change detection.

[fsnotify]: https://github.com/fsnotify/fsnotify

There are a number of edge cases with fsnotify based `fswatcher` and it is generally recommended to use the
stat()-based `pollwatcher` instead. Some issues to watch out for with the `fswatcher`:

1. Ordering of writes matters. Ensure that the external app that is writing the certificates writes the files in this order:
  .key first, .crt next.
2. If `mv` or `cp` is used to put new certificate/key files in place the updates will be missed.
3. If you pass a combined key and cert file to fwatcher, ensure the external app writes the new file in a single write(),
   otherwise the watcher will trigger a read of a partial cert.

Usage
-----

Create a watcher instance to watch for changes to your certificate files, then
create the certinel instance, pass your watcher instance, then start it with `Watch`.
Finally, pass the `GetCertificate` or `GetClientCertificate` method to your `tls.Config` instance.

Runnable examples are available in the [./examples](./examples) directory.