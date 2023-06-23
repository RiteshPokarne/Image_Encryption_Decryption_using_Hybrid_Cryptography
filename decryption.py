from PIL import Image
from aes_2 import *
from aes import *
from blowfish import *
from rsa import *
from encryption_file import *
#Initializations

decryption_key_aes = unhexlify(keys_iv['aes_key'])
decryption_iv_aes = unhexlify(keys_iv['aes_iv'])
decryption_key_rsa = RSA.construct(rsa_components = (keys_iv['rsa_n'] , keys_iv['rsa_e'] , keys_iv['rsa_d']))
decryption_iv_blowfish = unhexlify(keys_iv['blowfish_iv'])
decryption_key_blowfish = unhexlify(keys_iv['blowfish_key'])


aes_cipher_decryption = AES.new(decryption_key_aes, AES.MODE_CBC, iv=decryption_iv_aes)
rsa_cipher_decryption = PKCS1_OAEP.new(decryption_key_rsa)
blowfish_cipher_decryption = Blowfish.new(decryption_key_blowfish, Blowfish.MODE_CBC, iv=decryption_iv_blowfish)

# AES DECRYPTION
ciphertext_rsa = unpad(aes_cipher_decryption.decrypt(ciphertext), AES.block_size)
# RSA DECRYPTION
ciphertext_blowfish = bytearray()
for i in range(0, len(ciphertext_rsa),256):
    ciphertext_rsa_segment = ciphertext_rsa[i:i+256]
    ciphertext_blowfish.extend(rsa_cipher_decryption.decrypt(ciphertext_rsa_segment))
    
# BLOWFISH DECRYPTION
decrypted_plaintext = unpad(blowfish_cipher_decryption.decrypt(ciphertext_blowfish), Blowfish.block_size)

print(len(decrypted_plaintext))
with open("./test_files/flower2.png","wb") as f:
    f.write(decrypted_plaintext)
print("Image Decrypted succesfully")
img = Image.open("./test_files/flower2.png")
decrypt_hist = img.histogram()
plt.title("Histogram of Decrypted Image")
plt.xlabel("Intensity Value")
plt.ylabel("Frequency")
plt.plot(decrypt_hist)
plt.show()
#Initializations

decryption_key_aes = unhexlify(keys_iv['aes_key'])
decryption_iv_aes = unhexlify(keys_iv['aes_iv'])
decryption_key_rsa = RSA.construct(rsa_components = (keys_iv['rsa_n'] , keys_iv['rsa_e'] , keys_iv['rsa_d']))
decryption_iv_blowfish = unhexlify(keys_iv['blowfish_iv'])
decryption_key_blowfish = unhexlify(keys_iv['blowfish_key'])


aes_cipher_decryption = AES.new(decryption_key_aes, AES.MODE_CBC, iv=decryption_iv_aes)
rsa_cipher_decryption = PKCS1_OAEP.new(decryption_key_rsa)
blowfish_cipher_decryption = Blowfish.new(decryption_key_blowfish, Blowfish.MODE_CBC, iv=decryption_iv_blowfish)

# AES DECRYPTION
ciphertext_rsa = unpad(aes_cipher_decryption.decrypt(ciphertext), AES.block_size)
# RSA DECRYPTION
ciphertext_blowfish = bytearray()
for i in range(0, len(ciphertext_rsa),256):
    ciphertext_rsa_segment = ciphertext_rsa[i:i+256]
    ciphertext_blowfish.extend(rsa_cipher_decryption.decrypt(ciphertext_rsa_segment))
    
# BLOWFISH DECRYPTION
decrypted_plaintext = unpad(blowfish_cipher_decryption.decrypt(ciphertext_blowfish), Blowfish.block_size)

print(len(decrypted_plaintext))
with open("./test_files/flower2.png","wb") as f:
    f.write(decrypted_plaintext)
print("Image Decrypted succesfully")
img = Image.open("./test_files/flower2.png")
decrypt_hist = img.histogram()
plt.title("Histogram of Decrypted Image")
plt.xlabel("Intensity Value")
plt.ylabel("Frequency")
plt.plot(decrypt_hist)
plt.show()