defmodule Pbkdf2 do
  @moduledoc """
  """

  alias Pbkdf2.Base

  @doc """
  """
  def gen_salt(salt_len \\ 16), do: :crypto.strong_rand_bytes(salt_len)

  @doc """
  """
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, Keyword.get(opts, :salt_len, 16) |> gen_salt, opts)
  end

  @doc """
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
  """
  def no_user_verify do
    hash_pwd_salt("password")
    false
  end
end
