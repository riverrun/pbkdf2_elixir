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

  ## Warning

  It is recommended that you set a maximum length for the password
  when using Pbkdf2. This maximum length should not prevent valid users from setting
  long passwords. It is instead needed to combat denial-of-service attacks.
  As an example, Django sets the maximum length to `4096` bytes.
  For more information, see [this link](https://www.djangoproject.com/weblog/2013/sep/15/security/).
  """

  use Comeonin

  alias Pbkdf2.{Base, Tools}

  @doc """
  Generates a random salt.

  This function takes one optional argument - a keyword list (see below
  for options) or an integer with the salt length (in bytes).

  ## Options

  The following options are available:

    * `:salt_len` - the length of the random salt
      * the default is 16 bytes
      * for more information, see the 'Salt length recommendations' section below
    * `:format` - the length of the random salt
      * the default is `:modular` (modular crypt format)
      * the other available options are `:django` and `:hex`

  ## Examples

  Here is an example of generating a salt with the default salt length and format:

      Pbkdf2.gen_salt()

  To generate a different length salt:

      Pbkdf2.gen_salt(salt_len: 32)

  And to generate a salt in Django output format:

      Pbkdf2.gen_salt(format: :django)

  ## Salt length recommendations

  In most cases, 16 bytes is a suitable length for the salt.
  It is not recommended to use a salt that is shorter than this
  (see below for details and references).

  According to the [Pbkdf2 standard](https://tools.ietf.org/html/rfc8018),
  the salt should be at least 8 bytes long, but according to [NIST
  recommendations](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf),
  the minimum salt length should be 16 bytes.
  """
  @spec gen_salt(keyword | integer) :: binary
  def gen_salt(opts \\ [])

  def gen_salt(salt_len) when is_integer(salt_len) do
    gen_salt(salt_len: salt_len)
  end

  def gen_salt(opts) do
    salt_len = Keyword.get(opts, :salt_len, 16)
    Tools.check_salt_length(salt_len)

    case opts[:format] do
      :django -> Tools.get_random_string(salt_len)
      _ -> :crypto.strong_rand_bytes(salt_len)
    end
  end

  @doc """
  Hashes a password with a randomly generated salt.

  ## Options

  In addition to the options for `gen_salt/1` (`:salt_len` and `:format`),
  this function also takes options that are then passed on to the
  `hash_password` function in the `Pbkdf2.Base` module.

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
  @impl true
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, gen_salt(opts), opts)
  end

  @doc """
  Verifies a password by hashing the password and comparing the hashed value
  with a stored hash.

  See the documentation for `hash_pwd_salt/2` for examples of using this function.
  """
  @impl true
  def verify_pass(password, stored_hash) do
    [alg, rounds, salt, hash] = String.split(stored_hash, "$", trim: true)
    digest = if alg =~ "sha512", do: :sha512, else: :sha256
    Base.verify_pass(password, hash, salt, digest, rounds, output(stored_hash))
  end

  defp output("$pbkdf2" <> _), do: :modular
  defp output("pbkdf2" <> _), do: :django
end
