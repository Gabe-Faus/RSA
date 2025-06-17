from Crypto.Util.number import getPrime, inverse, GCD
# Essa biblioteca vai ser usada para geração de numeros primos acima de 1024 bits, Achar o MDC (GCD em inglês), e o inverso modular
# Use = pip install pycryptodome
import math
# Usaremos para verificar os fatores em comum por meio da função gcd que calcula quantos fatores em comum existem

""" Para implementar o algoritmo RSA devemos seguir os seguintes passos:
1 - Escolha dois numeros P e Q primos e que tem ao menos 1024 bits
2 - Calcule N = P*Q e Z = (P-1)*(Q-1) 
3 - Escolha E menor que N e que não tenha fatores em comum com Z além de 1
4 - Encontre um número D tal que ED - 1 seja exatamente divisivel - ou seja modulo ED mod Z = 1 - por Z 
5 - A chave pública KB+ será (N, E)e a chave privada KB- será (N, D)"""

def achar_chaves():
    p = int(getPrime(1024))  # Gera um primo de 1024 bits para a variavel p
    q = int(getPrime(1024)) # Gera um primo de 1024 bits para a variavel q
    while p == q:
        q = getPrime(1024) # Garante que p e q são diferentes
   
    n = int(p * q) # Aqui calculamos n
    z = int((p - 1)*(q - 1)) # Aqui calculamos z

    e = getPrime(1024)
    while GCD(e, z) != 1: # Aqui escolhemes E tal que o MDC de E e Z é diferente de 1
        e = getPrime(1024)

    d = inverse(e, z) # Calcula D que é o inverso modular de E e Z

    kbpublic = (n, e) # Esta eh a chave publica
    kbprivate = (n, d) # Esta eh a chave privada

    return kbpublic, kbprivate

achar_chaves()