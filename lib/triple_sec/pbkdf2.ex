defmodule TripleSec.Pbkdf2 do
  use Bitwise

  @max_length (1 <<< 32) - 1
  @salt_range 16..1024

  def pbkdf2(_password, _salt, iterations, _length, _prf)
    when iterations <= 0,
    do: raise ArgumentError, message: "iterations has to be positive"

  def pbkdf2(_password, _salt, _iterations, length, _prf)
    when length >= @max_length,
    do: raise ArgumentError, message: "length should be less than #{@max_length}"

  def pbkdf2(_password, salt, _iterations, _length, _prf)
    when not byte_size(salt) in @salt_range,
    do: raise ArgumentError, message: "salt size should be within #{inspect @salt_range}"

  def pbkdf2(password, salt, iterations, length, prf),
    do: pbkdf2(password, salt, iterations, length, prf, 1, [], 0)

  defp pbkdf2(password, salt, iterations, max_length, prf, block_ix, acc, length)
      when length < max_length do
    pseudo = prf.(password, <<salt::binary, block_ix::32>>)
    block = iterate(password, prf, iterations-1, pseudo, pseudo)
    pbkdf2(password, salt, iterations, max_length, prf, block_ix+1, [acc|block], length+byte_size(block))
  end
  defp pbkdf2(_password, _salt, _iterations, max_length, _prf, _block_ix, acc, _length) do
    <<result::binary-size(max_length), _::binary>> = IO.iodata_to_binary(acc)
    result
  end

  defp iterate(_password, _prf, 0, _prev, acc), do: acc
  defp iterate(password, prf, iteration, prev, acc) do
    next = prf.(password, prev)
    iterate(password, prf, iteration-1, next, :crypto.exor(next, acc))
  end

  def hmac_sha512 do
    &:crypto.hmac(:sha512, &1, &2)
  end
end
