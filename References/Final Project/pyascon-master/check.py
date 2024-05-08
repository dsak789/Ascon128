byte_sequence = b'Q\x07\x1b\xf1-G\xfe\x96\xa9z\xecq\xdf\x11\x1c:'
hex_representation = ''.join(format(byte, '02x') for byte in byte_sequence)

print(hex_representation)
