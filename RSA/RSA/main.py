from key_gen import *
from assinar import *
from oaep import *

if __name__ == "__main__":
    kbpublic, kbprivate = achar_chaves()# Gera as chaves
    print(f'\tEsta eh a chave publica: {kbpublic}\n\tEsta eh a chave privada {kbprivate}')# Mostra as chaves

    mensagem = b"Este eh um teste da mensagem secreta kkk" # Mensagem que passará pelo OAEP
    oaep = executar_oaep(mensagem) # Chama o método OAEP
    print(f"\n\tMensagem original: {oaep[0]}") # Mostra a mensagem original
    print(f"\n\tMensagem recuperada: {oaep[1]}") # Mostra mensagem recuperada
    print(f'\n\tOAEP feito com sucesso? {oaep[0]==oaep[1]}') # A mensagem é a mesma?

    mensagem = b"Aqui vai a mensagem secreta para assinar"# Mensagem que será assinada
    assinatura = assinar_mensagem(mensagem, kbprivate)# Cria a assinatura com a chave privada
    print("\n\tAssinatura base64:", assinatura)# Exibe a assinatura em Base64
    salvar_arquivo_assinado("mensagem_assinada.sig", mensagem, assinatura)# Salva a mensagem e a assinatura em um arquivo
    carregar_e_verificar_arquivo("mensagem_assinada.sig", kbpublic)
