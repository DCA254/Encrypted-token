from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt(
		token: bytes = None, 
		key: str = None
		) -> bytes:
	print("iniciando processo")
	print("token puro:", token)
	hex = key.replace("\\x", "") # troca todos os \x por "" ou seja, remove eles
	print("chave trocada:", hex)
	key_bytes = bytes.fromhex(hex) # pega a chave do hex
	print("chave em bytes:", key_bytes)
	nonce = token[:12] # nonce sao todos os caracteres ate o 12
	print("nonce:", nonce)
	tag = token[12:] # tag e todos os caracteres depois do 12
	print("tag:", tag)
	aesgcm = AESGCM(key_bytes) # basicamente dando uma tercerizada, poderia ter colocado
	print("aes:", aesgcm)
	decrypted = aesgcm.decrypt(nonce, tag, None) # bem aqui, direto tipo AESGCM(treco).decrypt(...)
												     # mas prefiri fazer assim pra ficar legivel, mesmo que
												     # custe eficiencia
	# vai printar no final de qualquer forma
	print("processo finalizado")
	return decrypted # retorna o resultado


	# esse e o algoritimo, bem mais simples que o outro tlg
	# agora bora usar ele




with open("hex_key.txt", "r") as f: # abre o arquivo pra ler, ta lendo como string, ou texto, ja que nao tem o "b"
	chave = f.read()

with open("layer_decriptografado.txt", "rb") as f: # agora que tem o "b" ta lendo como bytes, ou seja, binario
	criptografado = f.read() # o "r" e de read

descriptografado = decrypt(criptografado, chave)# usa a funcao que criamos antes, e coloca os treco como parametro, pra operar com eles

message = f"""
chave: {chave}



criptografado: {criptografado}



"""


print("",message, sep="\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")
print("", "descriptografado:", descriptografado, sep="\n\n\n")


with open("hex_decriptografado.txt", "wb") as f: # ta abrindo o arquivo para escrever binario
	f.write(descriptografado) # "w": "write", "b": "binary"



# como escrevi ele como bytes ele deve ser tratado como bytes tambem, e nao como texto
# mesmo que pareca texto

# o resto tambem continua simples
# so a primeira camada que ficava dificil tlg
# enfim, boa sorte agora
# vou so postar os treco no github e tambem o video no onedrive
# flw






