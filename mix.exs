defmodule Pbkdf2Elixir.Mixfile do
  use Mix.Project

  @version "0.12.3"

  @description """
  Pbkdf2 password hashing algorithm for Elixir
  """

  def project do
    [
      app: :pbkdf2_elixir,
      version: @version,
      elixir: "~> 1.4",
      start_permanent: Mix.env == :prod,
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
      {:earmark, "~> 1.2", only: :dev},
      {:ex_doc,  "~> 0.16", only: :dev}
    ]
  end

  defp package do
    [
      maintainers: ["David Whitlock"],
      licenses: ["BSD"],
      links: %{"GitHub" => "https://github.com/riverrun/pbkdf2_elixir",
        "Docs" => "http://hexdocs.pm/pbkdf2_elixir"}
    ]
  end
end
