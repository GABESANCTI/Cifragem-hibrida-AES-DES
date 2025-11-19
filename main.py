import cripto_funcoes as cf 
import base64
import os

def exibir_resultados(nome_variante, tempo_ms, texto_cifrado_b64, texto_decifrado, original):
    """Exibe os resultados de cifragem e decifragem de forma formatada"""
    print(f"\nRESULTADOS DA CIFRAGEM {nome_variante} ")
    print("")
    print(f"Tempo de Cifragem (Média de 100x): {tempo_ms:.4f} ms")
    print(f"Texto Cifrado (Base64): {texto_cifrado_b64}")
    print(f"Texto Decifrado: {texto_decifrado}")
    
    #status = "SUCESSO Cifragem e Decifragem Corretas." if texto_decifrado == original else "ERRO! Falha na Integridade."
    #print(f"Status: {status}") achei meio cringe ent deixei fora msm

def main():
    print("SISTEMA DE CIFRAGEM HÍBRIDA AES-DES")
    print("")
    print("")
  

    texto_plano = input("Digite o texto a ser cifrado: ")
    
    if not texto_plano:
        print("Texto não pode ser vazio :(  ")
        return

    texto_longo = texto_plano * 50 
    tamanho_dados_MB = len(texto_longo.encode('utf-8')) / (1024 * 1024)
    print(f"\n[INFO] Medição de desempenho será feita em uma carga de {tamanho_dados_MB:.2f} MB (50x o texto).")
    
    
    # VARIANTE A: CASCATA (AES -> DES -> AES)
    
    # Cifragem e Medição
    K1_A, K2_A, K3_A = cf.gerar_chaves_cascata()
    chaves_cascata_brutas = (K1_A, K2_A, K3_A) 
    
    tempo_cascata = cf.medir_desempenho(cf.cifrar_cascata_aes_des_aes, texto_longo, chaves_cascata_brutas)

    # Ciframos o texto original (curto) para exibição de I/O
    ciphertext_A, K1_A, K2_A, K3_A, IV1_A, IV2_A, IV3_A = cf.cifrar_cascata_aes_des_aes(texto_plano, K1_A, K2_A, K3_A)
    
    #Decifragem
    texto_decifrado_A = cf.decifrar_cascata_aes_des_aes(ciphertext_A, K1_A, K2_A, K3_A, IV1_A, IV2_A, IV3_A)
    
    # Exibição
    exibir_resultados("VARIANTE A (CASCATA)", tempo_cascata, base64.b64encode(ciphertext_A).decode(), texto_decifrado_A, texto_plano)

    
    # VARIANTE B: PARALELA AES DES

    # Cifragem e Medição
    KA_B, KD_B = cf.gerar_chaves_paralelas()
    chaves_paralelas_brutas = (KA_B, KD_B)
    
    tempo_paralela = cf.medir_desempenho(cf.cifrar_paralela, texto_longo, chaves_paralelas_brutas)
    
    # Ciframos o texto original (curto) para exibição de I/O
    ciphertext_B, KA_B, KD_B, IV_A_B, IV_D_B, tamanho_CA_B = cf.cifrar_paralela(texto_plano, KA_B, KD_B)

    # Decifragem
    texto_decifrado_B = cf.decifrar_paralela(ciphertext_B, KA_B, KD_B, IV_A_B, IV_D_B, tamanho_CA_B)

    # Exibição
    exibir_resultados("VARIANTE B (PARALELA)", tempo_paralela, base64.b64encode(ciphertext_B).decode(), texto_decifrado_B, texto_plano)


    # Comparação Final de Desempenho
    print("\nSUMÁRIO DE DESEMPENHO:")
    print("")
    print("")
    
    if tempo_cascata > tempo_paralela:
        diferenca_ms = tempo_cascata - tempo_paralela
        overhead_porcentagem = (diferenca_ms / tempo_paralela) * 100
        print(f"A Variante B (Paralela) eh a mais rapida :D")
        print(f"Overhead da Variante A (Cascata): {diferenca_ms:.4f} ms ({overhead_porcentagem:.2f}%) mais lenta.")
        print("")
        print("")
    else:
        diferenca_ms = tempo_paralela - tempo_cascata
        overhead_porcentagem = (diferenca_ms / tempo_cascata) * 100
        print(f"A Variante A (Cascata) eh a mais rapida!")
        print(f"Overhead da Variante B (Paralela): {diferenca_ms:.4f} ms ({overhead_porcentagem:.2f}%) mais lenta.")
        print("")
        print("")
    


if __name__ == "__main__":
    main()