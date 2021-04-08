defmodule Pbkdf2.Base do
  @moduledoc """
  Base module for the Pbkdf2 password hashing library.
  """

  use Bitwise
  alias Pbkdf2.{Base64, Tools}

  @max_length bsl(1, 32) - 1

  @deprecated "Use Pbkdf2.gen_salt/1 (with `format: :django`) instead"
  def django_salt(len) do
    Tools.get_random_string(len)
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
      * the default is `:modular` - modular crypt format
      * the other available formats are:
        * `:django` - the format used in django applications
        * `:hex` - the hash is encoded in hexadecimal
    * `:digest` - the sha algorithm that pbkdf2 will use
      * the default is sha512
    * `:length` - the length, in bytes, of the hash
      * the default is 64 for sha512 and 32 for sha256

  """
  @spec hash_password(binary, binary, keyword) :: binary
  def hash_password(password, salt, opts \\ []) do
    Tools.check_salt_length(byte_size(salt))
    {rounds, output_fmt, {digest, length}} = get_opts(opts)

    if length > @max_length do
      raise ArgumentError, "length must be equal to or less than #{@max_length}"
    end

    password
    |> create_hash(salt, digest, rounds, length)
    |> format(salt, digest, rounds, output_fmt)
  end

  @doc """
  Verify a password by comparing it with the stored Pbkdf2 hash.
  """
  @spec verify_pass(binary, binary, binary, atom, binary, atom) :: boolean
  def verify_pass(password, hash, salt, digest, rounds, output_fmt) do
    {salt, length} =
      case output_fmt do
        :modular -> {Base64.decode(salt), byte_size(Base64.decode(hash))}
        :django -> {salt, byte_size(Base.decode64!(hash))}
        :hex -> {salt, byte_size(Base.decode16!(hash, case: :lower))}
      end

    password
    |> create_hash(salt, digest, String.to_integer(rounds), length)
    |> encode(output_fmt)
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

  defp create_hash(password, salt, digest, rounds, length) do
    digest
    |> hmac_fun(password)
    |> do_create_hash(salt, rounds, length, 1, [], 0)
  end

  defp do_create_hash(_fun, _salt, _rounds, dklen, _block_index, acc, length)
       when length >= dklen do
    key = acc |> Enum.reverse() |> IO.iodata_to_binary()
    <<bin::binary-size(dklen), _::binary>> = key
    bin
  end

  defp do_create_hash(fun, salt, rounds, dklen, block_index, acc, length) do
    initial = fun.(<<salt::binary, block_index::integer-size(32)>>)
    block = iterate(fun, rounds - 1, initial, initial)

    do_create_hash(
      fun,
      salt,
      rounds,
      dklen,
      block_index + 1,
      [block | acc],
      byte_size(block) + length
    )
  end

  defp iterate(_fun, 0, _prev, acc), do: acc

  defp iterate(fun, round, prev, acc) do
    next = fun.(prev)
    iterate(fun, round - 1, next, :crypto.exor(next, acc))
  end

  defp format(hash, salt, digest, rounds, :modular) do
    "$pbkdf2-#{digest}$#{rounds}$#{Base64.encode(salt)}$#{Base64.encode(hash)}"
  end

  defp format(hash, salt, digest, rounds, :django) do
    "pbkdf2_#{digest}$#{rounds}$#{salt}$#{Base.encode64(hash)}"
  end

  defp format(hash, _salt, _digest, _rounds, :hex), do: Base.encode16(hash, case: :lower)

  defp encode(hash, :modular), do: Base64.encode(hash)
  defp encode(hash, :django), do: Base.encode64(hash)
  defp encode(hash, :hex), do: Base.encode16(hash, case: :lower)

  if System.otp_release() >= "22" do
    defp hmac_fun(digest, key), do: &:crypto.mac(:hmac, digest, key, &1)
  else
    defp hmac_fun(digest, key), do: &:crypto.hmac(digest, key, &1)
  end
end
