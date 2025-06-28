import base64 # importa um metodo
import json # mesma coisa
from cryptography.fernet import Fernet # importa isso dentro de 'cryptographer.fernet'
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 # mesma coisa
from cryptography.hazmat.primitives import serialization, hashes # denovo
from cryptography.hazmat.primitives.asymmetric import rsa, padding # denovo
from argon2.low_level import hash_secret_raw # denovo
from argon2.low_level import Type as ArgonType # denovo
from typing import Any # denovo

def _from_bytes(b: bytes) -> Any: # cria uma funcao, com o parametro 'b', que deve ser bytes
	try: # vai tentar dar um decode, pra virar 'texto' ou string
		s = b.decode("utf-8")
		return json.loads(s) # vai devolver ele dentro de um json, {s: treco aqui, b: treco aqui} so de exemplo
	except Exception: # caso o primeiro nao funcione
		return b # ele retorna o byte original fornecido, meio complexo demais pra explicar pq

def derive_key_argon2id(password: bytes, salt: bytes) -> bytes:
	return hash_secret_raw(
		secret=password,
		salt=salt,
		time_cost=3,
		memory_cost=65536,
		parallelism=1,
		hash_len=32,
		type=ArgonType.ID
	) # cria uma funcao que retorna o resultado disso ^, quando usar a funcao vai ser o mesmo que isso:





def decryption( # cria funcao
		Token: bytes,
		Key: bytes	
) -> Any: # avisa que vai retornar qualquer coisa, ou seja, o original
	meta_b64, layer = Token.split(b";;", 1) # vai pegar as informacoes de round, e declarar a layer
	rounds_info = json.loads(base64.b64decode(meta_b64).decode("utf-8")) # usando os rounds antes pegos, pega a quantidade
	for _ in reversed(rounds_info): # vai rodar isso pela quantidades de rounds usados na criptografacao
		layer = bytes.fromhex(layer.decode("utf-8")) # vai decodificar do hex
		layer = base64.b64decode(layer) # decodifica do base64
		f = Fernet(base64.urlsafe_b64encode(Key)) # f agora e um Fernet que guarda a chave encodificada, (a fornecida)
		layer = f.decrypt(layer) # usa o metodo de decryptografacao do Fernet criado anteriormente com a chave
		priv_b64, rsa_cipher = layer.split(b"::", 1) # pega a chave privada, e o encodificado
		priv_pem = base64.b64decode(priv_b64) # vai decodificar com base64 ou b64 a chave privada(que tava em b64)
		priv = serialization.load_pem_private_key(priv_pem, None) # declara a informacao privada, declarado anteriormente
		cipher_parts = rsa_cipher.split(b"||") # vai pegar as partes do ciphertext, que foi inserido no texto codificado, ou seja Token
		decrypted = [] # declara uma lista vazia, que vai ter os resultados adicionados depois
		for part in cipher_parts: # vai operar um loop dentro de cada parte em cipher parts
			enc = base64.b64decode(part) # decodifica a parte e coloca no enc
			decrypted.append(priv.decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))) # coloca na lista o resultado do priv.decrypt
		layer = b"".join(decrypted) # vai juntar cada parte daquela lista antes, em formato de bytes
		salt, nonce, ct = layer[:16], layer[16:28], layer[28:] # o salt vai ter os caracteres de bytes do 0~16, nonce vai ser do 16~28 e ct vai ser os chars em bytes de 28~final
		Key6 = derive_key_argon2id(Key, salt) # vai pegar a chave argonid, usando aquela funcao feita antes
		layer = ChaCha20Poly1305(Key6).decrypt(nonce, ct, None) # vai decodificar usando as coisas declaradas antes
		digest = hashes.Hash(hashes.SHA256()); digest.update(Key); k = digest.finalize() # 3 operacoes, mas basicamente vai 'decodificar' pra outro formato
		layer = bytes(b ^ k[i % len(k)] for i, b in enumerate(layer)) # layer agora vai ser uma lista, mas do que?, muito complexo pra explicar, e transforma a lista em bytes
		layer = layer[::-1] # inverte o layer, ou seja, inverte os bytes
		layer = bytes.fromhex(layer.decode("utf-8")) # decodifica o layer do formato hex
		layer = base64.b64decode(layer) # decodifica denovo
		f = Fernet(base64.urlsafe_b64encode(Key)) # declara o formato do Fernet, encodificando a chave fornecida por :D
		layer = f.decrypt(layer) # decodifica a layer com um fernet usando a chave nossa
	decrypted_data = _from_bytes(layer) # fora do loop dos rounds ja, ele pega o resultado, e transforma no original usando a funcao from bytes feita antes
	return decrypted_data # retorna o resultado

# vou explicar isso depois,
# se lembra que a chave layer deveria ser tratada em bytes?, vou mostrar como

with open("layer_key.txt", "rb") as f:
	key = f.read() # abre esse arquivo como bytes e coloca o conteudo (lido) numa variavel key
with open("encrypted_text.txt", "rb") as f:
	data_criptografada = f.read() # mesma coisa, porem para o criptografado

descriptografado = decryption(data_criptografada, key) # pega o treco descriptografado numa variavel

print(descriptografado) # mostra no terminal os bytes descriptografados

# agora vou escrever num arquivo, se lembra que quando mostrou no terminal, mostrou com 'b'?
# tem que operar com bytes entao


with open("layer_decriptografado.txt", "wb") as f:
	f.write(descriptografado)
# abre esse arquivo pra escrever binario (bytes)
# e escreve o descriptografado

# agora so falta voces descriptografarem o resto das camadas
# so pra avisar, essa (1 camada) era a mais complexa, o resto e tao facil que ate um bebe resolve
# se essa tomou 100 linhas de codigo, as outras da pra fazer em 10~20, sem nem precisar de conhecimento
# agora bora executar


















































