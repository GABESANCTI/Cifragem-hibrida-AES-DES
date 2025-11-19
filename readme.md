## DOCUMENTAÇÃO TÉCNICA: SISTEMA DE CIFRAGEM HÍBRIDA AES-DES

Documento referente a implementação de um sistema de criptografia híbrida que combina os algoritmos **AES (Advanced Encryption Standard)** e **DES (Data Encryption Standard)** em duas arquiteturas distintas: **Cascata (Variante A)** e **Paralela (Variante B)**. O projeto foi desenvolvido em Python para atender aos requisitos de um trabalho acadêmico em Segurança de Sistemas Computacionais.

***

## ARQUITETURA E ORGANIZAÇÃO

O código foi modularizado em dois arquivos principais para aderir às boas práticas de programação e garantir a legibilidade.

### CRIPTO\_FUNCOES.PY

Este módulo encapsula toda a lógica criptográfica e as funções de medição de desempenho.

| Função | Descrição |
| :--- | :--- |
| `gerar_chaves_cascata()` | Gera as três chaves: $K_1$ (AES 128-bit), $K_2$ (DES 56-bit) e $K_3$ (AES 128-bit) para a Variante A. |
| `gerar_chaves_paralelas()` | Gera as duas chaves: $K_A$ (AES 128-bit) e $K_D$ (DES 56-bit) para a Variante B. |
| `cifrar_cascata_aes_des_aes()` | Implementa a cifragem tripla sequencial $C = E_{AES}(K_3, E_{DES}(K_2, E_{AES}(K_1, P)))$. |
| `decifrar_cascata_aes_des_aes()` | Implementa a decifragem na ordem inversa da cifragem em cascata. |
| `cifrar_paralela()` | Divide o texto em $P_A$ e $P_D$ e realiza a cifragem concorrente (AES e DES). |
| `decifrar_paralela()` | Decifra as partes $C_A$ e $C_D$ e concatena o texto plano $P$. |
| `medir_desempenho()` | Função utilitária que cronometra o tempo médio de cifragem em um conjunto de 100 repetições para análise de *overhead*. |

### MAIN.PY

Este módulo gerencia a interface de entrada e saída (I/O), a execução das funções do módulo `cripto_funcoes.py` e a apresentação comparativa dos resultados de desempenho.

***

## ANÁLISE COMPARATIVA DAS VARIANTES

As duas variantes foram implementadas para comparar o *trade-off* entre **Segurança** e **Desempenho** no ambiente criptográfico.

### VARIANTE A: CIFRAGEM EM CASCATA

| Métrica | Descrição e Análise Teórica |
| :--- | :--- |
| **Arquitetura** | **Sequencial** (AES $\rightarrow$ DES $\rightarrow$ AES). Requer três passagens e três chaves independentes.  |
| **Segurança** | **Alta.** A estrutura tripla confere forte resistência contra o ataque **Meet-in-the-Middle (MITM)**. A segurança é maximizada ao custo de maior latência. |
| **Desempenho** | **Baixo.** O **alto *overhead*** é devido à execução sequencial de múltiplas cifras sobre o mesmo bloco de dados, somando os tempos individuais. |

### VARIANTE B: CIFRAGEM PARALELA

| Métrica | Descrição e Análise Teórica |
| :--- | :--- |
| **Arquitetura** | **Paralela** (AES $\parallel$ DES). Divide o texto plano em duas partes, cifradas simultaneamente.  |
| **Segurança** | **Limitada.** A segurança é definida pelo algoritmo mais fraco (**DES**, com 56 bits efetivos), deixando metade da mensagem teoricamente vulnerável à força bruta moderna. |
| **Desempenho** | **Alto.** O *overhead* é **baixo** porque o tempo de cifragem é dominado pelo algoritmo mais lento (AES) em metade da carga, permitindo paralelismo. |