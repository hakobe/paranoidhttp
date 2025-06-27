# Paranoidhttp

[![test](https://github.com/hakobe/paranoidhttp/actions/workflows/test.yml/badge.svg)](https://github.com/hakobe/paranoidhttp/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/hakobe/paranoidhttp/badge.svg?branch=master)][coveralls]
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)][license]
[![GoDoc](https://godoc.org/github.com/hakobe/paranoidhttp?status.svg)][godoc]

[travis]: https://travis-ci.org/hakobe/paranoidhttp
[coveralls]: https://coveralls.io/r/hakobe/paranoidhttp?branch=master
[license]: https://github.com/hakobe/paranoidhttp/blob/master/LICENSE
[godoc]: https://godoc.org/github.com/hakobe/paranoidhttp

Paranoidhttp provides a pre-configured http.Client that protects you from harm.

## Description

Paranoidhttp is a factory of http.Client that is paranoid againt attackers.
This is useful when you create an HTTP request using inputs from possibly malicious users.

The created http.Client protects you from connecting to internal IP ranges
even though redirects or DNS tricks are used.

## Synopsis

```go
// use the default client for ease
res, err := paranoidhttp.DefaultClient.Get("http://www.hatena.ne.jp")

// or customize the client for yourself
client, transport, dialer := paranoidhttp.NewClient()
client.Timeout = 10 * time.Second
transport.DisableCompression = true
dialer.KeepAlive = 60 * time.Second

// Add an permitted ipnets with functional option
ipNet, _ := net.ParseCIDR("127.0.0.1/32")
client, _, _ := paranoidhttp.New(
    paranoidhttp.PermittedIPNets(ipNet))
```

## Acknowledgement

I want to thank [LWPx::ParanoidAgent](https://metacpan.org/pod/LWPx::ParanoidAgent).

## License

[MIT](./LICENSE)

## Author

[hakobe](http://github.com/hakobe)
