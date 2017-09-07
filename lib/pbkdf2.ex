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

  ## Warning

  It is recommended that you set a maximum length for the password
  when using the `hash_pwd_salt`, `verify_pass` and `Base.hash_password`
  functions. This maximum length should not prevent valid users from setting
  long passwords. It is instead needed to combat denial-of-service attacks.
  As an example, Django sets the maximum length to 4096 bytes.
  For more information, see [this link](https://www.djangoproject.com/weblog/2013/sep/15/security/).
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
    raise ArgumentError, """
    The salt is the wrong length. It should be between 8 and 1024 bytes long.
    """
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
  Check the password by comparing it with the stored hash.

  The check is performed in constant time to avoid timing attacks.
  """
  def verify_pass(password, stored_hash) do
    [alg, rounds, salt, hash] = String.split(stored_hash, "$", trim: true)
    {digest, length} = if alg =~ "sha512", do: {:sha512, 64}, else: {:sha256, 32}
    Base.verify_pass(password, hash, salt, digest, rounds, length, output(stored_hash))
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

  defp output("$pbkdf2" <> _), do: :modular
  defp output("pbkdf2" <> _), do: :django
end
