defmodule Pbkdf2 do
  @moduledoc """
  Elixir wrapper for the Pbkdf2 password hashing function.

  For a lower-level API, see `Pbkdf2.Base`.

  ## Configuration

  The following parameter can be set in the config file:

    * `:rounds` - computational cost
      * the number of rounds
      * `160_000` is the default

  If you are hashing passwords in your tests, it can be useful to add
  the following to the `config/test.exs` file:

      # Note: Do not use this value in production
      config :pbkdf2_elixir,
        rounds: 1

  ## Pbkdf2

  Pbkdf2 is a password-based key derivation function
  that uses a password, a variable-length salt and an iteration
  count and applies a pseudorandom function to these to
  produce a key.

  The original implementation used SHA-1 as the pseudorandom function,
  but this version uses HMAC-SHA-512, the default, or HMAC-SHA-256.

  > ## Warning {: .warning}
  > It is recommended that you set a maximum length for the password
  > when using Pbkdf2. This maximum length should not prevent valid users from setting
  > long passwords. It is instead needed to combat denial-of-service attacks.
  > As an example, Django sets the maximum length to `4096` bytes.
  > For more information, see [this link](https://www.djangoproject.com/weblog/2013/sep/15/security/).
  """

  alias Pbkdf2.Base

  @doc """
  Hashes a password with a randomly generated salt.

  ## Options

  In addition to the options for `Pbkdf2.Base.gen_salt/1` (`:salt_len` and
  `:format`), this function also takes options that are then passed on to
  the `hash_password` function in the `Pbkdf2.Base` module.

  See the documentation for `Pbkdf2.Base.hash_password/3` for further details.

  ## Examples

  The following examples show how to hash a password with a randomly-generated
  salt and then verify a password:

      iex> hash = Pbkdf2.hash_pwd_salt("password")
      ...> Pbkdf2.verify_pass("password", hash)
      true

      iex> hash = Pbkdf2.hash_pwd_salt("password")
      ...> Pbkdf2.verify_pass("incorrect", hash)
      false

  The next examples show how to use some of the various available options:

      iex> hash = Pbkdf2.hash_pwd_salt("password", rounds: 100_000)
      ...> Pbkdf2.verify_pass("password", hash)
      true

      iex> hash = Pbkdf2.hash_pwd_salt("password", digest: :sha256)
      ...> Pbkdf2.verify_pass("password", hash)
      true

      iex> hash = Pbkdf2.hash_pwd_salt("password", digest: :sha256, format: :django)
      ...> Pbkdf2.verify_pass("password", hash)
      true

  """
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, Base.gen_salt(opts), opts)
  end

  @doc """
  Verifies a password by hashing the password and comparing the hashed value
  with a stored hash.

  See the documentation for `hash_pwd_salt/2` for examples of using this function.
  """
  def verify_pass(password, stored_hash) do
    [alg, rounds, salt, hash] = String.split(stored_hash, "$", trim: true)
    digest = if alg =~ "sha512", do: :sha512, else: :sha256
    Base.verify_pass(password, hash, salt, digest, rounds, output(stored_hash))
  end

  @doc """
  Runs the password hash function, but always returns false.

  This function is intended to make it more difficult for any potential
  attacker to find valid usernames by using timing attacks. This function
  is only useful if it is used as part of a policy of hiding usernames.

  > #### Note {: .note}
  > This function is resource-intensive. For a lighter alternative, consider 
  > adding a sleep delay to mimic the execution time of the hash function.

  ## Options

  This function should be called with the same options as those used by
  `hash_pwd_salt/2`.
  """
  def no_user_verify(opts \\ []) do
    hash_pwd_salt("", opts)
    false
  end

  defp output("$pbkdf2" <> _), do: :modular
  defp output("pbkdf2" <> _), do: :django
end
