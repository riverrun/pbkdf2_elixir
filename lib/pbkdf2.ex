defmodule Pbkdf2 do
  @moduledoc """
   Pbkdf2 password hashing library main module.

   This module implements the Comeonin and Comeonin.PasswordHash behaviours,
   providing the following functions:

     * `add_hash/2` - takes a password as input and returns a map containing the password hash
     * `check_pass/3` - takes a user struct and password as input and verifies the password
     * `no_user_verify/1` - runs the hash function, but always returns false
     * `hash_pwd_salt/2` - hashes the password with a randomly-generated salt
     * `verify_pass/2` - verifies a password

   For a lower-level API, see Pbkdf2.Base.

   ## Configuration

   The following parameter can be set in the config file:

     * rounds - computational cost
       * the number of rounds
       * 160_000 is the default

   If you are hashing passwords in your tests, it can be useful to add
   the following to the `config/test.exs` file:

       config :pbkdf2_elixir,
         rounds: 1

   NB. do not use this value in production.

   ## Options

   In addition to the options listed below, the `add_hash`, `no_user_verify`
   and `hash_pwd_salt` functions all take options that are then passed on
   to the `hash_password` function in the Pbkdf2.Base module.
   See the documentation for `Pbkdf2.Base.hash_password` for details.

   ### add_hash

     * `hash_key` - the key used in the map for the password hash
       * the default is `password_hash`
     * `:salt_len` - the length of the random salt
       * the default is 16 (the minimum is 8) bytes

   ### check_pass

     * `hash_key` - the key used in the user struct for the password hash
       * if this is not set, `check_pass` will look for `password_hash`, and then `encrypted_password`
     * `hide_user` - run `no_user_verify` to prevent user enumeration
       * the default is true
       * set this to false if you do not want to hide usernames

   ### hash_pwd_salt

     * `:salt_len` - the length of the random salt
       * the default is 16 (the minimum is 8) bytes

   ## Examples

   The following examples show how to hash a password with a randomly-generated
   salt and then verify a password:

       iex> hash = Pbkdf2.hash_pwd_salt("password")
       ...> Pbkdf2.verify_pass("password", hash)
       true

       iex> hash = Pbkdf2.hash_pwd_salt("password")
       ...> Pbkdf2.verify_pass("incorrect", hash)
       false

   ### add_hash

   The `put_pass_hash` function below is an example of how you can use
   `add_hash` to add the password hash to the Ecto changeset.

       defp put_pass_hash(%Ecto.Changeset{valid?: true, changes:
           %{password: password}} = changeset) do
         change(changeset, Pbkdf2.add_hash(password))
       end

       defp put_pass_hash(changeset), do: changeset

   This function will return a changeset with `%{password_hash: password_hash, password: nil}`
   added to the `changes` map.

   ### check_pass

   The following is an example of calling this function with no options:

      def verify_user(%{"password" => password} = params) do
        params
        |> Accounts.get_by()
        |> Bcrypt.check_pass(password)
      end

   The `Accounts.get_by` function in this example takes the user parameters
   (for example, email and password) as input and returns a user struct or nil.

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
   As an example, Django sets the maximum length to 4096 bytes.
   For more information, see [this link](https://www.djangoproject.com/weblog/2013/sep/15/security/).
  """

  use Comeonin

  alias Pbkdf2.Base

  @doc """
  Generate a random salt.

  The minimum length of the salt is 8 bytes and the maximum length is
  1024. The default length for the salt is 16 bytes. We do not recommend
  using a salt shorter than the default.
  """
  def gen_salt(salt_length \\ 16)

  def gen_salt(salt_length) when salt_length in 8..1024 do
    :crypto.strong_rand_bytes(salt_length)
  end

  def gen_salt(_) do
    raise ArgumentError, """
    The salt is the wrong length. It should be between 8 and 1024 bytes long.
    """
  end

  @impl true
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, Keyword.get(opts, :salt_len, 16) |> gen_salt, opts)
  end

  @impl true
  def verify_pass(password, stored_hash) do
    [alg, rounds, salt, hash] = String.split(stored_hash, "$", trim: true)
    digest = if alg =~ "sha512", do: :sha512, else: :sha256
    Base.verify_pass(password, hash, salt, digest, rounds, output(stored_hash))
  end

  defp output("$pbkdf2" <> _), do: :modular
  defp output("pbkdf2" <> _), do: :django
end
