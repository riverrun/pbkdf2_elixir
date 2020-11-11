defmodule Pbkdf2.BaseTest do
  use ExUnit.Case, async: false

  alias Pbkdf2.Base

  def check_vectors(data, digest \\ :sha512, format \\ :modular) do
    for {password, salt, rounds, stored_hash} <- data do
      opts = [rounds: rounds, digest: digest, format: format]
      assert Base.hash_password(password, salt, opts) == stored_hash
    end
  end

  test "base pbkdf2_sha512 tests" do
    [
      {
        "passDATAb00AB7YxDTT",
        "saltKEYbcTcXHCBxtjD",
        100_000,
        "$pbkdf2-sha512$100000$c2FsdEtFWWJjVGNYSENCeHRqRA$rM3Nh5iuXNhYBHOQFe8qEeMlkbe30W92gZswsNSdgOGr6myYIrgKH9/kIeJvVgPsqKR6ZMmgBPta.CKfdi/0Hw"
      },
      {
        "passDATAb00AB7YxDTTl",
        "saltKEYbcTcXHCBxtjD2",
        100_000,
        "$pbkdf2-sha512$100000$c2FsdEtFWWJjVGNYSENCeHRqRDI$WUJWsL1NbJ8hqH97pXcqeRoQ5hEGlPRDZc2UZw5X8a7NeX7x0QAZOHGQRMfwGAJml4Reua2X2X3jarh4aqtQlg"
      },
      {
        "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
        "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
        100_000,
        "$pbkdf2-sha512$100000$c2FsdEtFWWJjVGNYSENCeHRqRDJQbkJoNDRBSVE2WFVPQ0VTT2hYcEVwM0hyY0dNd2JqelFLTVNhZjYzSUpl$B0R0AchXZuSu1YPeLmv1pnXqvk82GCgclWFvT8H9/m7LwcOYJ4nU/ZQdZYTvU0p4vTeuAlVdlFXo8In9tN.2uw"
      }
    ]
    |> check_vectors
  end

  test "Python passlib pbkdf2_sha512 tests" do
    [
      {
        "password",
        <<36, 196, 248, 159, 51, 166, 84, 170, 213, 250, 159, 211, 154, 83, 10, 193>>,
        19_000,
        "$pbkdf2-sha512$19000$JMT4nzOmVKrV.p/TmlMKwQ$jKbZHoPwUWBT08pjb/CnUZmFcB9JW4dsOzVkfi9X6Pdn5NXWeY.mhL1Bm4V9rjYL5ZfA32uh7Gl2gt5YQa/JCA"
      },
      {
        "p@$$w0rd",
        <<252, 159, 83, 202, 89, 107, 141, 17, 66, 200, 121, 239, 29, 163, 20, 34>>,
        19_000,
        "$pbkdf2-sha512$19000$/J9TyllrjRFCyHnvHaMUIg$AJ3Dr926ltK1sOZMZAAoT7EoR7R/Hp.G6Bt.4DFENiYayhVM/ZBPuqjFNhcE9NjTmceTmLnSqzfEQ8mafy49sw"
      },
      {
        "oh this is hard 2 guess",
        <<1, 96, 140, 17, 162, 84, 42, 165, 84, 42, 165, 244, 62, 71, 136, 177>>,
        19_000,
        "$pbkdf2-sha512$19000$AWCMEaJUKqVUKqX0PkeIsQ$F0xkzJUOKaH8pwAfEwLeZK2/li6CF3iEcpfoJ1XoExQUTStXCNVxE1sd1k0aeQlSFK6JnxJOjM18kZIdzNYkcQ"
      },
      {
        "even more difficult",
        <<215, 186, 87, 42, 133, 112, 14, 1, 160, 52, 38, 100, 44, 229, 92, 203>>,
        19_000,
        "$pbkdf2-sha512$19000$17pXKoVwDgGgNCZkLOVcyw$TEv9woSaVTsYHLxXnFbWO1oKrUGfUAljkLnqj8W/80BGaFbhccG8B9fZc05RoUo7JQvfcwsNee19g8GD5UxwHA"
      }
    ]
    |> check_vectors
  end

  test "Consistency tests for sha512" do
    [
      {
        "funferal",
        <<192, 39, 248, 127, 11, 37, 71, 252, 74, 75, 244, 70, 129, 27, 51, 71>>,
        60_000,
        "$pbkdf2-sha512$60000$wCf4fwslR/xKS/RGgRszRw$QJHazw8zTaY0HvGQF1Slb07Ug9DFFLjoq63aORwhA.o/OM.e9UpxldolWyCNLv3duHuxpEWoZtGHfm3VTFCqpg"
      },
      {
        "he's N0t the Me551ah!",
        <<60, 130, 11, 97, 11, 23, 236, 250, 227, 233, 56, 1, 86, 131, 41, 163>>,
        60_000,
        "$pbkdf2-sha512$60000$PIILYQsX7Prj6TgBVoMpow$tsPUY4uMzTbJuv81xxZzsUGvT1LGjk9EfJuAYoZH9KaCSGH90J8BuQwY4Jb0JZbwOI00BSR4hDBVmn3Z8V.Ywg"
      },
      {
        "ἓν οἶδα ὅτι οὐδὲν οἶδα",
        <<29, 10, 228, 45, 215, 110, 213, 118, 168, 14, 197, 198, 67, 72, 34, 221>>,
        60_000,
        "$pbkdf2-sha512$60000$HQrkLddu1XaoDsXGQ0gi3Q$UVkPApVkIkQN0FTQwaKffYoZ5Mbh0712p1GWs9H1Z.fBNQScUWCj/GAUtZDYMkIN3kIi9ORvut.SQ7aBipcpDQ"
      }
    ]
    |> check_vectors
  end

  test "Consistency tests for sha256" do
    [
      {
        "funferal",
        <<192, 39, 248, 127, 11, 37, 71, 252, 74, 75, 244, 70, 129, 27, 51, 71>>,
        60_000,
        "$pbkdf2-sha256$60000$wCf4fwslR/xKS/RGgRszRw$p1XmqbB8u/EfvftMDoLyL4ZcVKT6Nz.Y4E/8xuoRePA"
      },
      {
        "he's N0t the Me551ah!",
        <<60, 130, 11, 97, 11, 23, 236, 250, 227, 233, 56, 1, 86, 131, 41, 163>>,
        80_000,
        "$pbkdf2-sha256$80000$PIILYQsX7Prj6TgBVoMpow$ErhanHiaHKh63nxft7nMS7rRpglbrZdQ6tEAhyrd.tQ"
      },
      {
        "ἓν οἶδα ὅτι οὐδὲν οἶδα",
        <<29, 10, 228, 45, 215, 110, 213, 118, 168, 14, 197, 198, 67, 72, 34, 221>>,
        100_000,
        "$pbkdf2-sha256$100000$HQrkLddu1XaoDsXGQ0gi3Q$egGo.5eQIb9Ulp27Xyc7WkesMu/u4mksXknuExBUCnc"
      }
    ]
    |> check_vectors(:sha256)
  end

  test "django format test vectors" do
    [
      {
        "pa$$word",
        "xvJitqXFKLDy",
        20_000,
        "pbkdf2_sha256$20000$xvJitqXFKLDy$CEzm5tv/2IVR5vT1pgN1B9ebo3n62xktmhClSuMsrM4="
      },
      {
        "passDATAb00AB7YxDTT",
        "7T4cGyTsIqXl",
        20_000,
        "pbkdf2_sha256$20000$7T4cGyTsIqXl$SGp9lb20DSYXk1SY80NxFlGPOIN8apThVNanlL628aw="
      },
      {
        "passDATAb00AB7YxDTTl",
        "pOIkJ2DADj78",
        20_000,
        "pbkdf2_sha256$20000$pOIkJ2DADj78$6/xhxGrCHGUJsQSs16V5s1GtucMSgGdtfVKmCyJsv58="
      },
      {
        "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
        "T1TgNUPEvPnc",
        20_000,
        "pbkdf2_sha256$20000$T1TgNUPEvPnc$OBc2b5qo+EoPbkPEr1m4Vcbc8ip2IYG/AfiiIgB4vcQ="
      }
    ]
    |> check_vectors(:sha256, :django)
  end

  test "configuring hash_password number of rounds" do
    Application.put_env(:pbkdf2_elixir, :rounds, 1)
    assert String.starts_with?(Base.hash_password("password", "somesalt"), "$pbkdf2-sha512$1$")
    Application.delete_env(:pbkdf2_elixir, :rounds)

    assert String.starts_with?(
             Base.hash_password("password", "somesalt"),
             "$pbkdf2-sha512$160000$"
           )
  end

  test "configuring output format" do
    salt = Pbkdf2.gen_salt(12)
    hash = Base.hash_password("password", salt, digest: :sha256)
    assert hash =~ "$pbkdf2-sha256"
    salt = Base.django_salt(12)
    hash = Base.hash_password("password", salt, digest: :sha256, format: :django)
    assert hash =~ "pbkdf2_sha256"
  end

  test "wrong length salt to hash_password" do
    assert_raise ArgumentError, ~r/The salt is the wrong length/, fn ->
      Base.hash_password("password", "salt")
    end
  end

  test "wrong length salt to hash_password with validation disabled" do
    hash = Base.hash_password("password", "salt", validate: false)

    assert hash ==
             "$pbkdf2-sha512$160000$c2FsdA$HN7oo2v9z2QCKXcSvky3cWU0nr42Q760yKIjspJW60DIOX4RWF/PGkQ9mMLM1VPidslMbMWzVYNRC3kqBiLeUg"
  end

  test "django salt only contains alphanumeric characters" do
    assert String.match?(Base.django_salt(12), ~r/^[A-Za-z0-9]*$/)
    assert String.match?(Base.django_salt(32), ~r/^[A-Za-z0-9]*$/)
  end

  test "raises when password or salt is nil to hash_password" do
    assert_raise ArgumentError, fn ->
      Base.hash_password(nil, "somesalt")
    end

    assert_raise ArgumentError, fn ->
      Base.hash_password("password", nil)
    end
  end
end
