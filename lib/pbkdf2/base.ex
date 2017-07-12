defmodule Pbkdf2.Base do
  @moduledoc """
  Base module for the Pbkdf2 password hashing library.
  """

  use Bitwise
  alias Pbkdf2.{Base64, Tools}

  @max_length bsl(1, 32) - 1

  @doc """
  Hash a password using Pbkdf2.

  ## Options

  There are four options:

    * rounds - the number of rounds
      * increasing this will make the hash function take longer and therefore make it more difficult to attack
      * the default is 160_000
    * output_fmt - the output format of the hash
      * the default is modular crypt format
    * digest - the sha algorithm that pbkdf2 will use
      * the default is sha512
    * length - the length, in bytes, of the hash
      * the default is 64 for sha512 and 32 for sha256

  """
  def hash_password(password, salt, opts \\ [])
  def hash_password(password, salt, opts)
      when is_binary(password) and is_binary(salt) and byte_size(salt) > 7 do
    {rounds, output_fmt, {digest, length}} = get_opts(opts)
    if length > @max_length do
      raise ArgumentError, "length must be equal to or less than #{@max_length}"
    end
    pbkdf2(password, salt, rounds, digest, length, 1, [], 0)
    |> format(salt, digest, rounds, output_fmt)
  end
  def hash_password(_, _, _) do
    raise ArgumentError, "The password and salt should be strings and " <>
      "the salt must be at least 8 bytes long"
  end

  @doc """
  Verify a password by comparing it with the stored Pbkdf2 hash.
  """
  def verify_pass(password, hash, salt, rounds, digest, length, output_fmt) do
    pbkdf2(password, Base64.decode(salt), String.to_integer(rounds), digest, length, 1, [], 0)
    |> verify_format(output_fmt)
    |> Tools.secure_check(hash)
  end

  defp get_opts(opts) do
    {Keyword.get(opts, :rounds, 160_000),
    Keyword.get(opts, :format, :modular),
    case opts[:digest] do
      :sha256 -> {:sha256, opts[:length] || 32}
      _ -> {:sha512, opts[:length] || 64}
    end}
  end

  defp pbkdf2(_password, _salt, _rounds, _digest, dklen, _block_index, acc, length)
      when length >= dklen do
    key = acc |> Enum.reverse |> IO.iodata_to_binary
    <<bin::binary-size(dklen), _::binary>> = key
    bin
  end
  defp pbkdf2(password, salt, rounds, digest, dklen, block_index, acc, length) do
    initial = :crypto.hmac(digest, password, <<salt::binary, block_index::integer-size(32)>>)
    block = iterate(password, rounds - 1, digest, initial, initial)
    pbkdf2(password, salt, rounds, digest, dklen, block_index + 1,
      [block | acc], byte_size(block) + length)
  end

  defp iterate(_password, 0, _digest, _prev, acc), do: acc
  defp iterate(password, round, digest, prev, acc) do
    next = :crypto.hmac(digest, password, prev)
    iterate(password, round - 1, digest, next, :crypto.exor(next, acc))
  end

  defp format(hash, salt, digest, rounds, :modular) do
    "$pbkdf2-#{digest}$#{rounds}$#{Base64.encode(salt)}$#{Base64.encode(hash)}"
  end
  defp format(hash, _salt, _digest, _rounds, :hex), do: Base.encode16(hash, case: :lower)

  defp verify_format(hash, _) do
    Base64.encode(hash)
  end
end
