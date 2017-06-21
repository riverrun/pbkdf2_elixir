defmodule Pbkdf2 do
  @moduledoc """
  """

  #use Bitwise
  import Pbkdf2.Base

  @doc """
  """
  def gen_salt(salt_len \\ 16)
  def gen_salt(salt_len) when salt_len in 16..1024 do
    :crypto.strong_rand_bytes(salt_len)
  end
  def gen_salt(_) do
    raise ArgumentError, "The salt is the wrong length"
  end

  @doc """
  """
  def hash_pwd_salt(password, opts \\ []) do
    hash_password(password, gen_salt(), opts)
  end

  @doc """
  """
  def verify_hash(hash, password, output_fmt \\ :modular)
  def verify_hash(hash, password, output_fmt) when is_binary(password) and is_binary(hash) do
    [_, alg, rounds, salt, hash] = String.split(hash, "$")
    {digest, length} = if alg == "pbkdf2-sha512", do: {:sha512, 64}, else: {:sha256, 32}
    verify_hash(hash, password, salt, rounds, digest, length, output_fmt)
  end
  def verify_hash(_, _, _) do
    raise ArgumentError, "Wrong type - password and salt should be strings"
  end

  @doc """
  """
  def no_user_verify do
    hash_pwd_salt("password")
    false
  end
end
