defmodule Scryptex.Scrypt do
  use Bitwise
  import Scryptex.Pbkdf2

  # Based on http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01

  @unit 4
  @hash_size 64

  def scrypt(pass, salt, cost, r, parallel, length) do
    scrypt(pass, salt, cost, r, parallel, 1, length)
  end

  def scrypt(pass, salt, cost, r, parallel, c, length) do
    mflen = 128 * r
    blocks = pbkdf2(pass, salt, c, mflen * parallel, &:crypto.hmac(:sha256, &1, &2))

    blocks = for <<x::32 <- blocks>>, into: "", do: <<x::little-32>>

    blocks = for <<block::binary-size(mflen) <- blocks>>, do: smix(block, cost, r, mflen)
    blocks = IO.iodata_to_binary(blocks)

    blocks = for <<x::little-32 <- blocks>>, into: "", do: <<x::32>>

    pbkdf2(pass, blocks, c, length, &:crypto.hmac(:sha256, &1, &2))
  end

  @doc false
  def smix(block, cost, r, mflen) do
    {vs, block} =
      Enum.reduce(1..cost, {[], block}, fn _, {vs, block} ->
        {[block | vs], blockmix_salsa8(block, mflen)}
      end)

    vs = vs |> Enum.reverse() |> List.to_tuple()

    block =
      Enum.reduce(1..cost, block, fn _, block ->
        j = integerify(block, r, cost)
        vj = elem(vs, j)
        :crypto.exor(block, vj) |> blockmix_salsa8(mflen)
      end)

    block
  end

  @doc false
  def blockmix_salsa8(block, mflen) do
    x = :binary.part(block, mflen - @hash_size, @hash_size)
    do_blockmix_salsa8(block, 0, x, "", "")
  end

  defp do_blockmix_salsa8(<<block::binary-size(@hash_size), rest::binary>>, ix, x, acc1, acc2) do
    x = :crypto.exor(x, block) |> salsa8

    if (ix &&& 1) == 0,
      do: do_blockmix_salsa8(rest, ix + 1, x, [acc1 | x], acc2),
      else: do_blockmix_salsa8(rest, ix + 1, x, acc1, [acc2 | x])
  end

  defp do_blockmix_salsa8(<<>>, _ix, _x, acc1, acc2) do
    IO.iodata_to_binary([acc1, acc2])
  end

  defp integerify(block, r, cost) do
    pos = 16 * (2 * r - 1) * @unit
    <<integer::size(@unit)-unit(8)>> = :binary.part(block, pos, @unit)
    integer &&& cost - 1
  end

  defp salsa8(input) do
    Scryptex.Salsa20.core(input, 8)
  end
end
