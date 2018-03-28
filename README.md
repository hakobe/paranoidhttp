# Paranoidhttp

[![Build Status](https://travis-ci.org/hakobe/paranoidhttp.svg?branch=master)](https://travis-ci.org/hakobe/paranoidhttp)

Paranoidhttp provides a pre-configured http.Client that protects you from harm.

## Description

Paranoidhttp is a factory of http.Client that is paranoid againt attackers.
This is useful when you craete a HTTP request using inputs from possibly malicious users.

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
```

## Known Issues

- Supports only IPv4 (blocks IPv6).

## Acknowledgement

I want to thank [LWPx::ParanoidAgent](https://metacpan.org/pod/LWPx::ParanoidAgent).

## License

[MIT](./LICENSE)

## Author

[hakobe](http://github.com/hakobe)
