defmodule Pbkdf2 do
  @moduledoc """
  Pbkdf2 password hashing library main module.

  For a lower-level API, see Pbkdf2.Base.
  """

  alias Pbkdf2.Base

  @doc """
  Generate a random salt.

  The default length for the salt is 16 bytes. We do not recommend using
  a salt shorter than the default.
  """
  def gen_salt(salt_len \\ 16), do: :crypto.strong_rand_bytes(salt_len)

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
  """
  def verify_hash(stored_hash, password, output_fmt \\ :modular)
  def verify_hash(stored_hash, password, output_fmt) when is_binary(password) do
    [alg, rounds, salt, hash] = String.split(stored_hash, "$", trim: true)
    {digest, length} = if alg == "pbkdf2-sha512", do: {:sha512, 64}, else: {:sha256, 32}
    Base.verify_hash(hash, password, salt, rounds, digest, length, output_fmt)
  end
  def verify_hash(_, _, _) do
    raise ArgumentError, "Wrong type - password and salt should be strings"
  end

  @doc """
  A dummy verify function to help prevent user enumeration.

  This function hashes the password and then returns false, and it is
  intended to make it more difficult for any potential attacker to find
  valid usernames by using timing attacks. This function is only useful
  if it is used as part of a policy of hiding usernames. For more information,
  see the section below on username obfuscation.

  It is important that this function is called with the same options
  that are used to hash the password.

  ## Example

  The following example looks for the user in the database and checks the
  password with the stored password hash if the user is found. It then
  returns the user struct, if the password is correct, or false. If no user
  is found, the `no_user_verify` function is called. This will take the same
  time to run as the `verify_hash` function. This means that the end user
  will not be able to find valid usernames just by timing the responses.

      def verify_password(username, password) do
        case Repo.get_by(User, username: username) do
          nil -> Pbkdf2.no_user_verify()
          user -> Pbkdf2.verify_hash(user.password_hash, password) && user
        end
      end

  ## Username obfuscation

  In addition to keeping passwords secret, hiding the precise username
  can help make online attacks more difficult. An attacker would then
  have to guess a username / password combination, rather than just
  a password, to gain access.

  This does not mean that the username should be kept completely secret.
  Adding a short numerical suffix to a user's name, for example, would be
  sufficient to increase the attacker's work considerably.

  If you are implementing a policy of hiding usernames, it is important
  to make sure that the username is not revealed by any other part of
  your application.
  """
  def no_user_verify do
    hash_pwd_salt("password")
    false
  end
end
