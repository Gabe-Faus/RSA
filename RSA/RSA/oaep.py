import hashlib
import os
from key_gen import achar_chaves

def sha3_256(mensagem):
    return hashlib.sha3_256(mensagem).digest() # Aqui estamos fazendo o hash SHA-3 da  mensagem 

def mgf1(semente, tamanho, hash_func=hashlib.sha3_256):
    hashlen = hash_func().digest_size
    mascara = b""
    for counter in range((tamanho + hashlen - 1) // hashlen):
        C = counter.to_bytes(4, byteorder='big')
        mascara += hash_func(semente + C).digest()
    return mascara[:tamanho]

"""Aqui calculamos a Mascara (Masck Generation Function 1) que usamosno OAEP. A partir de uma semente geramos uma mascara de comprimento tamanho. Aplicamos o hasch sobre a semente + counter"""

def oaep_codificar(mensagem: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha3_256) -> bytes: 
    mensagemlen = len(mensagem)
    hashlen = hash_func().digest_size

    if mensagemlen > k -2 * hashlen - 2:
        raise ValueError("Mensagem longa demais")
    
    label_hash = hash_func(label).digest()
    PS = b'\x00' * (k - mensagemlen - 2 * hashlen - 2)
    DB = label_hash + PS + b'\x01' + mensagem
    semente = os.urandom(hashlen)
    mascara_db = mgf1(semente, k - hashlen - 1, hash_func)
    db_mascarado = bytes(a ^ b for a, b in zip(DB, mascara_db)) 
    semente_mascara = mgf1(db_mascarado, hashlen, hash_func)
    semente_mascarada = bytes(a ^ b for a, b in zip(semente, semente_mascara))
    return b'\x00' + semente_mascarada + db_mascarado

""""Aplicamos o OAEP na mensagem original usando SHA3-256, k é o numero de bytes do bloco RSA, aqui adicionamos aleatoridade e padding segura a mensagem.

Geramos um hash do label (label_hash) que geralmente esta vazio, depois criamos um DB = label_hash + padding + 0x01 + mensagem, geramos uma semente aleatória de 32 bytes e usamos o MFG1 para mascarar DB e a semente retorna o ME (mensagem encriptada) final: 0x00 || semente mascarada || DB mascarado"""

def oaep_decodificar(ME: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha3_256) -> bytes:
    hashlen = hash_func().digest_size
    if len(ME) != k or ME[0] != 0x00:
        raise ValueError("Bloco inválido")
    
    semente_mascarada = ME[1:hashlen+1]
    db_mascarado = ME[hashlen+1:]

    semente_mascara = mgf1(db_mascarado, hashlen, hash_func)
    semente = bytes(a ^ b for a,b in zip(semente_mascarada, semente_mascara))
    mascara_db = mgf1(semente, k - hashlen - 1, hash_func)
    DB = bytes(a ^ b for a,b in zip(db_mascarado, mascara_db))

    label_hash = hash_func(label).digest()
    if DB[:hashlen] != label_hash:
        raise ValueError("Label hash inválido")
    
    i = DB.find(b'\x01', hashlen)
    if i == -1:
        raise ValueError("Delimitador 0x01 não encontrado")
    return DB[i+1:]

"""Aqui revertemos o processo de codificaçao de OAEP, extraimos a mensagem origianl de ME (mensagem encriptada) e verificamos se o label bate com o hash e localizamos a marca 0x01

Extraimos semente_mascaradas e db_mascarado, desmascara os dois usando MGF1, verificamos label_hash no ínicio de DB, Procuramos o byte 0x01 como separador entre o padding e a mensagem. No fim retornamos a mensagen"""

def executar_oaep(mensagem):
    #Aqui geramos as chaves
    chaves = achar_chaves()
    kbpublic = chaves[0]
    kbprivate = chaves[1]

    n, e = kbpublic
    n_priv, d = kbprivate

    k = (kbpublic[0].bit_length() + 7) // 8

    #Aqui codificamos com o OAEP
    me = oaep_codificar(mensagem, k)

    #Criptografar com o RSA
    m_inteiro = int.from_bytes(me, 'big')
    c_inteiro = pow(m_inteiro, e, n)
    criptograma = c_inteiro.to_bytes(k, 'big')

    #Descriptografar com RSA
    c_inteiro = int.from_bytes(criptograma, 'big')
    m_decod_inteiro = pow(c_inteiro, d, n)
    m_decod = m_decod_inteiro.to_bytes(k, 'big')

    #Aqui decodificamos o OAEP
    mensagem_recuperada = oaep_decodificar(m_decod, k)

    return mensagem, mensagem_recuperada

