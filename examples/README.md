examples
========

This directory contains examples of how to use this library.

pollwatcher/pollwatcher_example.go
----------------------

Demonstrates using the `stat()` based pollwatcher package.

```sh
# create a self-signed cert - tls.key, tls.crt:
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 7 -subj '/C=US/L=California/CN=testing-only/'

go run pollwatcher/pollwatcher_example.go

curl -k https://localhost:8000

# run openssl again to generate a new cert. It should be reloaded on the next poll-interval
```

If you need to create an expired cert pass a negative value to the `-days` flag. Note that this only seems to work in OpenSSL 1.0.x

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days -1 -subj '/C=US/L=California/CN=testing-only/'
```

fswatcher/fswatcher_example.go
----------------------

Demonstrates using the [fsnotify](https://github.com/fsnotify/fsnotify) (inotify) based fswatcher package.

```sh
go run fswatcher/fswatcher_example.go
```
