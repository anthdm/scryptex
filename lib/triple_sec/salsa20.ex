defmodule TripleSec.Salsa20 do
  use Bitwise

  @int32_max :math.pow(2, 32) |> trunc

  defp sum(x, y), do: (x+y) &&& (@int32_max-1)
  defp rotl(x, n), do: ((x<<<n) ||| (x>>>(32-n))) &&& (@int32_max-1)

  @doc false
  def quarterround(y0, y1, y2, y3) do
    z1 = y1 ^^^ (sum(y0, y3) |> rotl(7))
    z2 = y2 ^^^ (sum(z1, y0) |> rotl(9))
    z3 = y3 ^^^ (sum(z2, z1) |> rotl(13))
    z0 = y0 ^^^ (sum(z3, z2) |> rotl(18))

    {z0, z1, z2, z3}
  end

  @doc false
  def rowround({y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15}) do
    { z0,  z1,  z2,  z3} = quarterround( y0,  y1,  y2,  y3)
    { z5,  z6,  z7,  z4} = quarterround( y5,  y6,  y7,  y4)
    {z10, z11,  z8,  z9} = quarterround(y10, y11,  y8,  y9)
    {z15, z12, z13, z14} = quarterround(y15, y12, y13, y14)

    {z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15}
  end

  @doc false
  def columnround({x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15}) do
    { y0,  y4,  y8, y12} = quarterround( x0,  x4,  x8, x12)
    { y5,  y9, y13,  y1} = quarterround( x5,  x9, x13,  x1)
    {y10, y14,  y2,  y6} = quarterround(x10, x14,  x2,  x6)
    {y15,  y3,  y7, y11} = quarterround(x15,  x3,  x7, x11)

    {y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15}
  end

  def doubleround(x), do: x |> columnround |> rowround

  defp doublerounds(x, 0), do: x
  defp doublerounds(x, n), do: x |> doubleround |> doublerounds(n-1)

  def hash(input, rounds \\ 20) when byte_size(input) == 64 and rem(rounds, 2) == 0 do
    x = for(<<word::little-32 <- input>>, do: word)

    z =
      List.to_tuple(x)
      |> doublerounds(div(rounds, 2))
      |> Tuple.to_list

    Enum.zip(x, z)
    |> Enum.map(fn {xn, yn} -> <<sum(xn, yn)::little-32>> end)
    |> IO.iodata_to_binary
  end
end
