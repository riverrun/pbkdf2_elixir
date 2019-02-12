defmodule Pbkdf2Elixir.Mixfile do
  use Mix.Project

  @version "1.0.0"

  @description """
  Pbkdf2 password hashing algorithm for Elixir
  """

  def project do
    [
      app: :pbkdf2_elixir,
      version: @version,
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      description: @description,
      package: package(),
      source_url: "https://github.com/riverrun/pbkdf2_elixir",
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:comeonin, "~> 5.0"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["David Whitlock"],
      licenses: ["BSD"],
      links: %{"GitHub" => "https://github.com/riverrun/pbkdf2_elixir"}
    ]
  end
end
