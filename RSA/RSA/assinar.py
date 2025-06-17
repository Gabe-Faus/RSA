import base64
import hashlib

def assinar_mensagem(mensagem: bytes, chave_privada: tuple) -> str:
    n, d = chave_privada# Extrai os componentes da chave privada RSA
    hash_mensagem = hashlib.sha3_256(mensagem).digest()# Aplica o hash SHA3-256 na mensagem original (em bytes)
    hash_int = int.from_bytes(hash_mensagem, 'big')# Converte o hash de bytes pra inteiro para usar no RSA
    assinatura = pow(hash_int, d, n)# Cria a assinatura: assinatura = (hash)^d mod n (RSA)
    assinatura_bytes = assinatura.to_bytes((n.bit_length() + 7) // 8, 'big')# Converte a assinatura de inteiro para bytes
    return base64.b64encode(assinatura_bytes).decode('utf-8')  # Codifica a assinatura em base64


def verificar_assinatura(mensagem: bytes, assinatura_b64: str, chave_publica: tuple) -> bool:
    n, e = chave_publica# Extrai os componentes da chave pública RSA
    assinatura_bytes = base64.b64decode(assinatura_b64)# Decodifica a assinatura de base64 pra bytes
    assinatura_int = int.from_bytes(assinatura_bytes, 'big')# Converte a assinatura de bytes para inteiro pra aplicar RSA
    hash_verificado = pow(assinatura_int, e, n)# Decifra o hash com a chave publica: hash_verificado = assinatura^e mod n
    hash_calculado = int.from_bytes(hashlib.sha3_256(mensagem).digest(), 'big')# Calcula o hash SHA3-256 da mensagem original
    return hash_verificado == hash_calculado# Compara os dois hashes: se forem iguais, a assinatura é válida


def salvar_arquivo_assinado(nome_arquivo, mensagem: bytes, assinatura_b64: str):
    with open(nome_arquivo, 'w') as f:
        f.write(base64.b64encode(mensagem).decode('utf-8') + "\n")# Escreve a mensagem original codificada em base64
        f.write(assinatura_b64)# Escreve a assinatura codificada em base64


def carregar_e_verificar_arquivo(nome_arquivo, chave_publica: tuple):
    with open(nome_arquivo, 'r') as f:
        mensagem_b64 = f.readline().strip()# Lê a mensagem codificada e a assinatura linha por linha
        assinatura_b64 = f.readline().strip()
    mensagem = base64.b64decode(mensagem_b64)# Decodifica a mensagem de base64 pra bytes
    valido = verificar_assinatura(mensagem, assinatura_b64, chave_publica)# Verifica se a assinatura é válida com a chave pública
    print("Assinatura válida!" if valido else "Assinatura inválida.")# Resultado


