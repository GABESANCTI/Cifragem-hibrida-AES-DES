import time
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# CONSTANTES DE BLOCO
BLOCK_SIZE_AES = 16 # 128 bits
BLOCK_SIZE_DES = 8  # 64 bits

# FUNÇÕES DE SUPORTE E GERAÇÃO DE CHAVES

def gerar_chaves_cascata():
    """Gera K1 (AES 128-bit), K2 (DES 56-bit) e K3 (AES 128-bit)."""
    K1 = get_random_bytes(BLOCK_SIZE_AES)
    K3 = get_random_bytes(BLOCK_SIZE_AES)
    K2 = get_random_bytes(BLOCK_SIZE_DES) 
    return K1, K2, K3

def gerar_chaves_paralelas():
    """Gera KA (AES 128-bit) e KD (DES 56-bit)."""
    KA = get_random_bytes(BLOCK_SIZE_AES)
    KD = get_random_bytes(BLOCK_SIZE_DES)
    return KA, KD

# FUNÇÕES DE ENCRYPT e DECRYPT

# VARIANTE A: CASCATA (AES -> DES -> AES)

def cifrar_cascata_aes_des_aes(plaintext, K1, K2, K3):
    """Cifra o texto plano usando AES(K1) -> DES(K2) -> AES(K3)."""
    IV1 = get_random_bytes(BLOCK_SIZE_AES) 
    cipher_aes1 = AES.new(K1, AES.MODE_CBC, IV1)
    padded_data = pad(plaintext.encode('utf-8'), BLOCK_SIZE_AES) 
    intermediario1 = cipher_aes1.encrypt(padded_data)
    
    IV2 = get_random_bytes(BLOCK_SIZE_DES) 
    cipher_des = DES.new(K2, DES.MODE_CBC, IV2)
    intermediario2 = cipher_des.encrypt(intermediario1)
    
    IV3 = get_random_bytes(BLOCK_SIZE_AES) 
    cipher_aes3 = AES.new(K3, AES.MODE_CBC, IV3)
    intermediario2_padded = pad(intermediario2, BLOCK_SIZE_AES)
    ciphertext = cipher_aes3.encrypt(intermediario2_padded)
    
    # Retorna o texto cifrado, todas as chaves, e todos os IVs
    return ciphertext, K1, K2, K3, IV1, IV2, IV3

def decifrar_cascata_aes_des_aes(ciphertext, K1, K2, K3, IV1, IV2, IV3):
    """Decifra o texto cifrado na ordem inversa: D_AES(K3) -> D_DES(K2) -> D_AES(K1)."""
    decipher_aes3 = AES.new(K3, AES.MODE_CBC, IV3)
    intermediario2_padded = decipher_aes3.decrypt(ciphertext)
    intermediario2 = unpad(intermediario2_padded, BLOCK_SIZE_AES)
    
    decipher_des = DES.new(K2, DES.MODE_CBC, IV2)
    intermediario1 = decipher_des.decrypt(intermediario2)
    
    decipher_aes1 = AES.new(K1, AES.MODE_CBC, IV1)
    padded_data = decipher_aes1.decrypt(intermediario1)
    plaintext = unpad(padded_data, BLOCK_SIZE_AES)
    
    return plaintext.decode('utf-8')

# VARIANTE B: PARALELA 

def cifrar_paralela(plaintext, KA, KD):
    """Cifra o texto plano dividindo-o em duas partes cifradas por AES e DES em paralelo."""
    data_bytes = plaintext.encode('utf-8')
    ponto_divisao = len(data_bytes) // 2
    P_A = data_bytes[:ponto_divisao]
    P_D = data_bytes[ponto_divisao:]

    # Cifragem de P_A (AES)
    IV_A = get_random_bytes(BLOCK_SIZE_AES) 
    cipher_aes = AES.new(KA, AES.MODE_CBC, IV_A)
    padded_A = pad(P_A, BLOCK_SIZE_AES) 
    C_A = cipher_aes.encrypt(padded_A)
    tamanho_CA = len(C_A)
    
    # Cifragem de P_D (DES)
    IV_D = get_random_bytes(BLOCK_SIZE_DES) 
    cipher_des = DES.new(KD, DES.MODE_CBC, IV_D)
    padded_D = pad(P_D, BLOCK_SIZE_DES) 
    C_D = cipher_des.encrypt(padded_D)
    
    ciphertext = C_A + C_D
    
    # Retorna o texto cifrado, chaves, IVs e o tamanho de C_A (para decifragem)
    return ciphertext, KA, KD, IV_A, IV_D, tamanho_CA

def decifrar_paralela(ciphertext, KA, KD, IV_A, IV_D, tamanho_CA):
    """Decifra o texto cifrado e junta as partes decifradas."""
    C_A = ciphertext[:tamanho_CA]
    C_D = ciphertext[tamanho_CA:]
    
    # Decifragem de C_A (AES)
    decipher_aes = AES.new(KA, AES.MODE_CBC, IV_A)
    P_A_padded = decipher_aes.decrypt(C_A)
    P_A = unpad(P_A_padded, BLOCK_SIZE_AES)
    
    # Decifragem de C_D (DES)
    decipher_des = DES.new(KD, DES.MODE_CBC, IV_D)
    P_D_padded = decipher_des.decrypt(C_D)
    P_D = unpad(P_D_padded, BLOCK_SIZE_DES)
    
    plaintext_bytes = P_A + P_D
    
    return plaintext_bytes.decode('utf-8')

# MÓDULO DE MEDIÇÃO DE DESEMPENHO

def medir_desempenho(funcao_cifragem, texto_plano, chaves_brutas):
    """Mede o tempo médio de cifragem em milissegundos (ms)."""
    
    num_repeticoes = 100 
    tempos = []
    
    # Desempacota as chaves de forma genérica para a chamada da função
    chaves = tuple(chaves_brutas) 
    
    # Executa a função e mede o tempo
    for _ in range(num_repeticoes):
        inicio = time.perf_counter() 
        
        # Chama a função de cifragem usando desempacotamento de tupla
        funcao_cifragem(texto_plano, *chaves)
            
        fim = time.perf_counter() 
        tempos.append((fim - inicio) * 1000) # Tempo em milissegundos (ms)

    tempo_medio_ms = sum(tempos) / num_repeticoes
    return tempo_medio_ms