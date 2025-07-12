# bora comecar os treco pra descriptografar
# essa 3 camada e BEM simples

from Crypto.Cipher import AES
# import a biblioteca que vamos usar 
# importa 'AES'

def decrypt(
		token: bytes = None, # parametro token, esperado bytes
		key: bytes = None, # mesma coisa, esperado bytes
		) -> bytes: # retorna bytes
	payload = bytes.fromhex(token.decode("utf-8"))
	# token.decode transforma os bytes em string(texto), e em seguida pega essa string
	# que era uma string hex e transforma numa pura
	key_bytes = bytes.fromhex(key.decode("utf-8"))
	# mesma coisa porem para a chave
	iv = payload[:12] # tudo do payload ate o caractere 12
	tag = payload[12:28] # tudo do payload desde o caractere 12 ate o 28
	ciphertext = payload[28:] # todo o resto do payload a partir do caractere 28
	cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv) # usa a biblioteca importada antes
	# para fazer um procedimento, que seria muito trabalhoso de explicar
	decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
	# descriptografa usando essa funcao da biblioteca importada e como os parametros os ciphertext e tag
	return decrypted_data # retorna o valor descriptografado

# essa e a funcao para descriptografar
# agora bora pegar as chaves e tokens

# se lembra que a chave e em bytes
# e o token tambem



with open("hex_decriptografado.txt", "rb") as f:
	token = f.read()
# pega o token, lendo ele como bytes
# por isso o 'r' 'b' -> "read binary" ou "read bytes"

with open("binary_key.txt", "rb") as f:
	key = f.read()


descriptografado = decrypt(token, key)


print("", "", sep="\n\n\n\n\n\n\n\n\n")
print("token:", token, sep="\n\n\n\n\n\n\n\n")
print("key:", key, sep="\n\n\n\n\n\n\n\n\n")
print("descriptografado:", descriptografado, sep="\n\n\n\n\n\n\n")

# agora vamo passar isso pra os arquivos


with open("binary_descriptografado.txt", "wb") as f:
	f.write(descriptografado)

# escreve o descriptografado, escrevendo ele como bytes
# por isso o 'r' 'b' -> "write binary" ou "write bytes"

# na real e so isso, agora vamo comentar o codigo


# e foi so isso, como falei, as ultimas camadas sao as mais simples
# agora falta poucas para voces
# boa sorte ai
# vou so colocar o video la no onedrive e mandar esse treco no github junto com os token descriptografado
# boa sorte no resto 
# kkkkkkkkkkkkkkkkkkkkkkkkkk
















