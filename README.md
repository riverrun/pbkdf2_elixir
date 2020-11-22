# Pbkdf2

[![Hex.pm Version](http://img.shields.io/hexpm/v/pbkdf2_elixir.svg)](https://hex.pm/packages/pbkdf2_elixir)
[![Build Status](https://travis-ci.com/riverrun/pbkdf2_elixir.svg?branch=master)](https://travis-ci.com/riverrun/pbkdf2_elixir)

Pbkdf2 password hashing library for Elixir.

Pbkdf2 is a well-tested password-based key derivation function that can be
configured to remain slow and resistant to brute-force attacks even as
computational power increases.

## Comparison with the Plug.Crypto version of Pbkdf2

If you want the Pbkdf2 output to be in binary (raw) or hex format, you might
find [Plug.Crypto.KeyGenerator](https://hexdocs.pm/plug_crypto/Plug.Crypto.KeyGenerator.html)
more convenient.

## Installation

1. Add pbkdf2_elixir to the `deps` section of your mix.exs file:

```elixir
def deps do
  [
    {:pbkdf2_elixir, "~> 1.3"}
  ]
end
```

2. Optional: during tests (and tests only), you may want to reduce the number of rounds
so it does not slow down your test suite. If you have a config/test.exs, you should
add:

```elixir
config :pbkdf2_elixir, :rounds, 1
```

## Comeonin wiki

See the [Comeonin wiki](https://github.com/riverrun/comeonin/wiki) for more
information on the following topics:

* [algorithms](https://github.com/riverrun/comeonin/wiki/Choosing-the-password-hashing-algorithm)
* [requirements](https://github.com/riverrun/comeonin/wiki/Requirements)
* [deployment](https://github.com/riverrun/comeonin/wiki/Deployment)
  * including information about using Docker
* [references](https://github.com/riverrun/comeonin/wiki/References)

## Contributing

There are many ways you can contribute to the development of this library, including:

* reporting issues
* improving documentation
* sharing your experiences with others
* [making a financial contribution](#donations)

## Donations

First of all, I would like to emphasize that this software is offered
free of charge. However, if you find it useful, and you would like to
buy me a cup of coffee, you can do so at [paypal](https://www.paypal.me/alovedalongthe).

### Documentation

http://hexdocs.pm/pbkdf2_elixir

### License

BSD.
