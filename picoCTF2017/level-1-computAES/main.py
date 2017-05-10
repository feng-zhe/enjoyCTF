from Crypto.Cipher import AES
from binascii import a2b_base64

encryption = 'rvn6zLZS4arY+yWNwZ5YlbLAv/gjwM7gZJnqyQjhRZVCC5jxaBvfkRapPBoyxu4e' 
key = '/7uAbKC7hfINLcSZE+Y9AA=='
cipher = AES.new(a2b_base64(key), AES.MODE_ECB)
decoded = cipher.decrypt(a2b_base64(encryption))
print decoded
