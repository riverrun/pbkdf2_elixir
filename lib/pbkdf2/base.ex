defmodule Pbkdf2.Base do
  @moduledoc """
  """

  use Bitwise
  alias Pbkdf2.{Base64, Tools}

  @doc """
  """
  def hash_password(password, salt, opts \\ [])
  def hash_password(password, salt, opts) when is_binary(password) and is_binary(salt) do
    {rounds, output_fmt, {digest, length}} = get_opts(opts)
    pbkdf2(password, salt, rounds, digest, length) |> format(salt, rounds, output_fmt)
  end
  def hash_password(_, _, _) do
    raise ArgumentError, "Wrong type - password and salt should be strings"
  end

  @doc """
  """
  def verify_hash(hash, password, salt, rounds, digest, length, output_fmt) do
    pbkdf2(password, Base64.decode(salt), String.to_integer(rounds), digest, length)
    |> verify_format(output_fmt)
    |> Tools.secure_check(hash)
  end

  defp pbkdf2(password, salt, rounds, digest, length) when byte_size(salt) in 16..1024 do
    pbkdf2(password, salt, rounds, digest, length, 1, [], 0)
  end
  defp pbkdf2(_password, _salt, _rounds, _digest, _length) do
    raise ArgumentError, "The salt is the wrong length."
  end

  defp get_opts(opts) do
    {Keyword.get(opts, :rounds, 160_000),
    Keyword.get(opts, :format, :modular),
    case opts[:digest] do
      :sha256 -> {:sha256, 32}
      _ -> {:sha512, 64}
    end}
  end

  defp pbkdf2(_password, _salt, _rounds, _digest, max_length, _block_index, acc, length)
      when length >= max_length do
    key = acc |> Enum.reverse |> IO.iodata_to_binary
    <<bin::binary-size(max_length), _::binary>> = key
    bin
  end
  defp pbkdf2(password, salt, rounds, digest, max_length, block_index, acc, length) do
    initial = :crypto.hmac(digest, password, <<salt::binary, block_index::integer-size(32)>>)
    block = iterate(password, rounds - 1, digest, initial, initial)
    pbkdf2(digest, password, salt, rounds, max_length, block_index + 1,
    [block | acc], byte_size(block) + length)
  end

  defp iterate(_password, 0, _digest, _prev, acc), do: acc
  defp iterate(password, round, digest, prev, acc) do
    next = :crypto.hmac(digest, password, prev)
    iterate(password, round - 1, digest, next, :crypto.exor(next, acc))
  end

  defp format(hash, salt, rounds, :modular) do
    "$pbkdf2-sha512$#{rounds}$#{Base64.encode(salt)}$#{Base64.encode(hash)}"
  end
  defp format(hash, _salt, _rounds, :hex), do: Base.encode64(hash)

  defp verify_format(hash, :modular) do
    Base64.encode(hash)
  end
end
