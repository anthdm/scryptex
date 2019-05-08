defmodule Scryptex.ScryptTest do
  use ExUnit.Case, async: true
  import Scryptex.Scrypt

  defp hex_to_binary(input) do
    input
    |> String.replace(~r"\s", "")
    |> Base.decode16!(case: :lower)
  end

  defp endian_reverse(input) do
    for <<x::32 <- input>>, into: "", do: <<x::little-32>>
  end

  defp check_vectors(list) do
    Enum.each(list, fn {pass, salt, cost, r, parallel, c, length, output} ->
      assert scrypt(pass, salt, cost, r, parallel, c, length) == hex_to_binary(output)
    end)
  end

  # From http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-8
  test "blockmix_salsa8" do
    input =
      endian_reverse(
        hex_to_binary("""
        f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
        77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
        89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
        09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
        89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
        cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
        67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
        7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
        """)
      )

    output =
      endian_reverse(
        hex_to_binary("""
        a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
        04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
        b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
        e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81
        20 ed c9 75 32 38 81 a8 05 40 f6 4c 16 2d cd 3c
        21 07 7c fe 5f 8d 5f e2 b1 a4 16 8f 95 36 78 b7
        7d 3b 3d 80 3b 60 e4 ab 92 09 96 e5 9b 4d 53 b6
        5d 2a 22 58 77 d5 ed f5 84 2c b9 f1 4e ef e4 25
        """)
      )

    assert blockmix_salsa8(input, 128) == output
  end

  # From http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-9
  test "smix" do
    input =
      endian_reverse(
        hex_to_binary("""
        f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
        77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
        89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
        09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
        89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
        cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
        67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
        7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
        """)
      )

    output =
      endian_reverse(
        hex_to_binary("""
        79 cc c1 93 62 9d eb ca 04 7f 0b 70 60 4b f6 b6
        2c e3 dd 4a 96 26 e3 55 fa fc 61 98 e6 ea 2b 46
        d5 84 13 67 3b 99 b0 29 d6 65 c3 57 60 1f b4 26
        a0 b2 f4 bb a2 00 ee 9f 0a 43 d1 9b 57 1a 9c 71
        ef 11 42 e6 5d 5a 26 6f dd ca 83 2c e5 9f aa 7c
        ac 0b 9c f1 be 2b ff ca 30 0d 01 ee 38 76 19 c4
        ae 12 fd 44 38 f2 03 a0 e4 e1 c4 7e c3 14 86 1f
        4e 90 87 cb 33 39 6a 68 73 e8 f9 d2 53 9a 4b 8e
        """)
      )

    assert smix(input, 16, 1, 128) == output
  end

  # From http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-11
  #
  # BUT, note we made a change and lowered the constants here, lest we
  # take forever to run the regression tests. The new data is from
  # https://github.com/keybase/Scryptex/blob/4b81c60de65f6072a51032833b1a1cbd618bfb05/test/files/scrypt.iced.
  test "scrypt" do
    [
      {"", "", 16, 1, 1, 1, 64,
       """
       77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
       f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
       fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
       e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
       """},
      {"pleaseletmein", "SodiumChloride", 1024, 8, 1, 1, 64,
       """
       54 17 36 87 d2 65 e4 32 26 bd 91 4b 01 52 67 e2
       fd d4 10 8a a0 59 37 fb 54 9e ce b0 c2 76 a2 85
       fe 59 e2 29 3f 5a a3 fe 28 8f 0e 7e 55 27 90 da
       a4 d8 d7 9c 09 29 46 63 15 2a cb 71 9d d2 25 b8
       """},
      {"password", "NaCl", 64, 8, 16, 1, 64,
       """
       7e 9c 6d 04 bd 24 20 13 da aa ce 3a d2 38 33 da
       9f ed 1f df a6 0c 56 72 c0 5a ce 9a b2 f2 40 fe
       a7 9a 44 7b 85 9f 74 78 d7 b4 a1 c1 59 65 cf 71
       64 06 99 75 5e a3 75 aa 8e 32 17 d7 41 9d 12 00
       """},
      {"password", "NaCl", 64, 8, 16, 256, 64,
       """
       e0 f4 b0 56 83 1b 35 bf a2 fd 58 e8 e7 4e 45 95
       cd 6b 3c 9d 88 30 73 96 45 bf ff 78 31 ed 37 fb
       da 2f 15 cd f4 4a c2 a9 0c f5 29 5d 3c 39 55 60
       2d 1c 0b ea 76 58 ee 65 c5 2a e6 1c fc 65 fe 21
       """}
    ]
    |> check_vectors
  end

  @tag :slow
  test "slow scrypt" do
    [
      {"blah3blah4", "saltandpepper", 16384, 8, 1, 1, 64,
       """
       41 16 d2 b4 fd d5 2a a5 d2 53 9b 85 6f c9 f2 4c
       18 ca ed f1 92 ee 13 af b2 82 80 11 f4 90 f4 57
       0c 8f e2 eb 80 04 21 c1 13 f1 51 11 ec 85 44 c3
       83 14 0a 4a ad 85 31 33 11 63 bd ee e9 0d 56 62
       """}
    ]
    |> check_vectors
  end
end
