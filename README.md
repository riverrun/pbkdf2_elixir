# Pbkdf2

Pbkdf2 password hashing algorithm for Elixir.

Pbkdf2 is a well-tested password-based key derivation function that can be
configured to remain slow and resistant to brute-force attacks even as
computational power increases.

This library can be used on its own, or it can be used together
with [Comeonin](https://hexdocs.pm/comeonin/api-reference.html),
which provides a higher-level api.

## Installation

1. Add pbkdf2_elixir to the `deps` section of your mix.exs file:

```elixir
def deps do
  [
    {:pbkdf2_elixir, "~> 0.12"}
  ]
end
```

2. Optional: during tests (and tests only), you may want to reduce the number of rounds
so it does not slow down your test suite. If you have a config/test.exs, you should
add:

```elixir
config :pbkdf2_elixir, :rounds, 1
```

## Use

In most cases, you will just need to use the following three functions:

* hash_pwd_salt - hash a password with a randomly-generated salt
* verify_pass - check the password by comparing it with a stored hash
* no_user_verify - perform a dummy check to make user enumeration more difficult

See the documentation for the Pbkdf2 module for more information.

For a lower-level api, see the documentation for Pbkdf2.Base.

### License

BSD.
