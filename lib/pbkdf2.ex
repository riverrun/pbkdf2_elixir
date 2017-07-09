defmodule Pbkdf2 do
  @moduledoc """
  Pbkdf2 password hashing library main module.

  For a lower-level API, see Pbkdf2.Base.

  ## Pbkdf2

  Pbkdf2 is a password-based key derivation function
  that uses a password, a variable-length salt and an iteration
  count and applies a pseudorandom function to these to
  produce a key.

  The original implementation used SHA-1 as the pseudorandom function,
  but this version uses HMAC-SHA-512, the default, or HMAC-SHA-256.
  """

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
    raise ArgumentError, "The salt is the wrong length."
  end

  @doc """
  Generate a random salt and hash a password using Pbkdf2.

  ## Options

  For more information about the options for the underlying hash function,
  see the documentation for Pbkdf2.Base.hash_password/3.

  This function has the following additional option:

    * salt_len - the length of the random salt
      * the default is 16 (the minimum is 8) bytes
      * we do not recommend using a salt less than 16 bytes long

  """
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, Keyword.get(opts, :salt_len, 16) |> gen_salt, opts)
  end

  @doc """
  Verify an encoded Pbkdf2 hash.

  ## Options

  There is one option:

    * output_fmt - the output format of the hash
      * the default is modular crypt format

  """
  def verify_hash(stored_hash, password, opts \\ [])
  def verify_hash(stored_hash, password, opts) when is_binary(password) do
    [alg, rounds, salt, hash] = String.split(stored_hash, "$", trim: true)
    {digest, length} = if alg == "pbkdf2-sha512", do: {:sha512, 64}, else: {:sha256, 32}
    Base.verify_hash(hash, password, salt, rounds, digest, length, opts[:output_fmt])
  end
  def verify_hash(_, _, _) do
    raise ArgumentError, "Wrong type - password and salt should be strings"
  end

  @doc """
  A dummy verify function to help prevent user enumeration.

  This always returns false. The reason for implementing this check is
  in order to make it more difficult for an attacker to identify users
  by timing responses.
  """
  def no_user_verify(opts \\ []) do
    hash_pwd_salt("password", opts)
    false
  end
end
