defmodule Pbkdf2.Stats do
  @moduledoc """
  """

  alias Pbkdf2.Base64

  @doc """
  """
  def report(password, salt, opts \\ []) do
    {exec_time, encoded} = :timer.tc(Pbkdf2.Base, :hash_password, [password, salt, opts])
    Pbkdf2.verify_hash(encoded, password)
    |> format_result(encoded, exec_time)
  end

  defp format_result(check, encoded, exec_time) do
    [_, alg, rounds, _, hash] = String.split(encoded, "$")
    IO.puts """
    Digest: #{alg}
    Digest length: #{Base64.decode(hash) |> byte_size}
    Rounds: #{rounds}
    #{format_time(exec_time)} seconds
    Verification #{if check, do: "ok", else: "failed"}
    """
  end

  defp format_time(time) do
    Float.round(time / 1_000_000, 2)
  end
end
