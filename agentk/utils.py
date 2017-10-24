def bigint_to_bytes(num, extra_bytes=0):
    return num.to_bytes(length=((num.bit_length() + 7) // 8) + extra_bytes, byteorder='big')
