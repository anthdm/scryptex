defmodule TripleSec.Salsa20 do
  use Bitwise

  @int32_max 1 <<< 32

  @compile {:inline, sum: 2, rotl: 2}

  defp sum(x, y), do: (x+y) &&& (@int32_max-1)
  defp rotl(x, n), do: (x<<<n ||| (x>>>(32-n))) &&& (@int32_max-1)

  def hash(input, rounds \\ 20)

  def hash(input, _rounds) when byte_size(input) != 64,
    do: raise ArgumentError, message: "input has to be 64 bytes"

  def hash(_input, rounds) when rem(rounds, 2) != 0,
    do: raise ArgumentError, message: "rounds has to be dividable by 2"

  def hash(input, rounds) do
    # NOTE: This is 5-10% slower than manually inlining core/2 in this function

    <<x0::32,  x1::32,  x2::32,  x3::32,
      x4::32,  x5::32,  x6::32,  x7::32,
      x8::32,  x9::32,  x10::32, x11::32,
      x12::32, x13::32, x14::32, x15::32>> =
    for(<<x::little-32 <- input>>, into: "", do: <<x::32>>) |> core(rounds)

    <<x0::little-32,  x1::little-32,  x2::little-32,  x3::little-32,
      x4::little-32,  x5::little-32,  x6::little-32,  x7::little-32,
      x8::little-32,  x9::little-32,  x10::little-32, x11::little-32,
      x12::little-32, x13::little-32, x14::little-32, x15::little-32>>
  end

  def core(input, rounds \\ 20)

  def core(input, _rounds) when byte_size(input) != 64,
    do: raise ArgumentError, message: "input has to be 64 bytes"

  def core(_input, rounds) when rem(rounds, 2) != 0,
    do: raise ArgumentError, message: "rounds has to be dividable by 2"

  def core(input, rounds) do
    original = for(<<x::32 <- input>>, do: x) |> List.to_tuple
    {y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15} = original

    {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15} =
      Enum.reduce(1..div(rounds, 2), original, fn _, tuple ->
        {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15} = tuple

        u = sum(x0 , x12); x4  = x4  ^^^ rotl(u, 7)
        u = sum(x4 , x0 ); x8  = x8  ^^^ rotl(u, 9)
        u = sum(x8 , x4 ); x12 = x12 ^^^ rotl(u, 13)
        u = sum(x12, x8 ); x0  = x0  ^^^ rotl(u, 18)
        u = sum(x5 , x1 ); x9  = x9  ^^^ rotl(u, 7)
        u = sum(x9 , x5 ); x13 = x13 ^^^ rotl(u, 9)
        u = sum(x13, x9 ); x1  = x1  ^^^ rotl(u, 13)
        u = sum(x1 , x13); x5  = x5  ^^^ rotl(u, 18)
        u = sum(x10, x6 ); x14 = x14 ^^^ rotl(u, 7)
        u = sum(x14, x10); x2  = x2  ^^^ rotl(u, 9)
        u = sum(x2 , x14); x6  = x6  ^^^ rotl(u, 13)
        u = sum(x6 , x2 ); x10 = x10 ^^^ rotl(u, 18)
        u = sum(x15, x11); x3  = x3  ^^^ rotl(u, 7)
        u = sum(x3 , x15); x7  = x7  ^^^ rotl(u, 9)
        u = sum(x7 , x3 ); x11 = x11 ^^^ rotl(u, 13)
        u = sum(x11, x7 ); x15 = x15 ^^^ rotl(u, 18)
        u = sum(x0 , x3 ); x1  = x1  ^^^ rotl(u, 7)
        u = sum(x1 , x0 ); x2  = x2  ^^^ rotl(u, 9)
        u = sum(x2 , x1 ); x3  = x3  ^^^ rotl(u, 13)
        u = sum(x3 , x2 ); x0  = x0  ^^^ rotl(u, 18)
        u = sum(x5 , x4 ); x6  = x6  ^^^ rotl(u, 7)
        u = sum(x6 , x5 ); x7  = x7  ^^^ rotl(u, 9)
        u = sum(x7 , x6 ); x4  = x4  ^^^ rotl(u, 13)
        u = sum(x4 , x7 ); x5  = x5  ^^^ rotl(u, 18)
        u = sum(x10, x9 ); x11 = x11 ^^^ rotl(u, 7)
        u = sum(x11, x10); x8  = x8  ^^^ rotl(u, 9)
        u = sum(x8 , x11); x9  = x9  ^^^ rotl(u, 13)
        u = sum(x9 , x8 ); x10 = x10 ^^^ rotl(u, 18)
        u = sum(x15, x14); x12 = x12 ^^^ rotl(u, 7)
        u = sum(x12, x15); x13 = x13 ^^^ rotl(u, 9)
        u = sum(x13, x12); x14 = x14 ^^^ rotl(u, 13)
        u = sum(x14, x13); x15 = x15 ^^^ rotl(u, 18)

        {x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15}
      end)

    <<sum(y0,  x0)::32,  sum(y1,  x1)::32,  sum(y2,  x2)::32,  sum(y3,  x3)::32,
      sum(y4,  x4)::32,  sum(y5,  x5)::32,  sum(y6,  x6)::32,  sum(y7,  x7)::32,
      sum(y8,  x8)::32,  sum(y9,  x9)::32,  sum(y10, x10)::32, sum(y11, x11)::32,
      sum(y12, x12)::32, sum(y13, x13)::32, sum(y14, x14)::32, sum(y15, x15)::32>>
  end
end
