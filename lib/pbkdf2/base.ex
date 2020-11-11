defmodule Pbkdf2.Base do
  @moduledoc """
  Base module for the Pbkdf2 password hashing library.
  """

  use Bitwise
  alias Pbkdf2.{Base64, Tools}

  @max_length bsl(1, 32) - 1

  @doc """
  Generate a salt for use with Django's version of pbkdf2.

  ## Examples

  To create a valid Django hash, using pbkdf2_sha256:

      salt = django_salt(12)
      opts = [digest: :sha256, format: :django]
      Pbkdf2.Base.hash_password(password, salt, opts)

  This example uses 160_000 rounds. Add `rounds: number` to the opts
  if you want to change the number of rounds.
  """
  def django_salt(len) do
    :crypto.strong_rand_bytes(len * 2)
    |> Pbkdf2.Base64.encode()
    |> String.replace(~r{[.|/]}, "")
    |> :binary.part(0, len)
  end

  @doc """
  Hash a password using Pbkdf2.

  ## Options

  There are four options (rounds can be used to override the value
  in the config):

    * `:rounds` - the number of rounds
      * the amount of computation, given in number of iterations
      * the default is 160_000
      * this can also be set in the config file
    * `:format` - the output format of the hash
      * the default is modular crypt format
    * `:digest` - the sha algorithm that pbkdf2 will use
      * the default is sha512
    * `:length` - the length, in bytes, of the hash
      * the default is 64 for sha512 and 32 for sha256
    * `:validate` - whether the salt length should be validated
      * the default is true, which means an `ArgumentError` is raised unless
        the salt length is between 8 and 1024 bytes long

  """
  def hash_password(password, salt, opts \\ [])

  def hash_password(password, salt, opts) do
    unless byte_size(salt) in 8..1024 or opts[:validate] == false do
      raise ArgumentError, """
      The salt is the wrong length. It should be between 8 and 1024 bytes long.
      """
    end

    {rounds, output_fmt, {digest, length}} = get_opts(opts)

    if length > @max_length do
      raise ArgumentError, "length must be equal to or less than #{@max_length}"
    end

    password
    |> pbkdf2(salt, digest, rounds, length, 1, [], 0)
    |> format(salt, digest, rounds, output_fmt)
  end

  @doc """
  Verify a password by comparing it with the stored Pbkdf2 hash.
  """
  def verify_pass(password, hash, salt, digest, rounds, output_fmt) do
    {salt, length} =
      case output_fmt do
        :modular -> {Base64.decode(salt), byte_size(Pbkdf2.Base64.decode(hash))}
        _ -> {salt, byte_size(Base.decode64!(hash))}
      end

    password
    |> pbkdf2(salt, digest, String.to_integer(rounds), length, 1, [], 0)
    |> verify_format(output_fmt)
    |> Tools.secure_check(hash)
  end

  defp get_opts(opts) do
    {
      Keyword.get(opts, :rounds, Application.get_env(:pbkdf2_elixir, :rounds, 160_000)),
      Keyword.get(opts, :format, :modular),
      case opts[:digest] do
        :sha256 -> {:sha256, opts[:length] || 32}
        _ -> {:sha512, opts[:length] || 64}
      end
    }
  end

  defp pbkdf2(_password, _salt, _digest, _rounds, dklen, _block_index, acc, length)
       when length >= dklen do
    key = acc |> Enum.reverse() |> IO.iodata_to_binary()
    <<bin::binary-size(dklen), _::binary>> = key
    bin
  end

  defp pbkdf2(password, salt, digest, rounds, dklen, block_index, acc, length) do
    initial = :crypto.hmac(digest, password, <<salt::binary, block_index::integer-size(32)>>)
    block = iterate(password, digest, rounds - 1, initial, initial)

    pbkdf2(
      password,
      salt,
      digest,
      rounds,
      dklen,
      block_index + 1,
      [block | acc],
      byte_size(block) + length
    )
  end

  defp iterate(_password, _digest, 0, _prev, acc), do: acc

  defp iterate(password, digest, round, prev, acc) do
    next = :crypto.hmac(digest, password, prev)
    iterate(password, digest, round - 1, next, :crypto.exor(next, acc))
  end

  defp format(hash, salt, digest, rounds, :modular) do
    "$pbkdf2-#{digest}$#{rounds}$#{Base64.encode(salt)}$#{Base64.encode(hash)}"
  end

  defp format(hash, salt, digest, rounds, :django) do
    "pbkdf2_#{digest}$#{rounds}$#{salt}$#{Base.encode64(hash)}"
  end

  defp format(hash, _salt, _digest, _rounds, :hex), do: Base.encode16(hash, case: :lower)

  defp verify_format(hash, :modular), do: Base64.encode(hash)
  defp verify_format(hash, :django), do: Base.encode64(hash)
  defp verify_format(hash, _), do: hash
end
