# 0053. Os segredos aparecem junto do servidor que os usa

**Status:** Accepted — 10 nov 2026. Detalha a aba "MCP Servers / APIs" de
`0051`. É uma mudança de **apresentação**: o isolamento do cofre e o portão de
root de `0050` §2 ficam exatamente como estão.

## Contexto

O cofre (`0018`, `0005`) guarda os valores que as entradas do registro nomeiam.
A aba Secrets (`0050` §2) mostrava todos os nomes numa tela separada do backend
que os consome, então para responder "esta API tem o que precisa para subir?" o
operador cruzava duas telas. Os nomes de segredo que uma entrada declara já vêm
no detalhe do upstream (`GetUpstream`, `0050` §2) e no que o cofre reporta
(`ListSecrets`: nomes, se há valor, e quais entradas declaram cada nome).

## Decisão

### 1. Os segredos de um backend aparecem no detalhe dele

A página de detalhe de um "MCP server / API" (`0051`) mostra, inline, os nomes
de segredo que **aquela** entrada declara, cada um com o estado "no cofre" ou
"faltando", e os botões de gravar e apagar valor. É um recorte da mesma lista do
cofre pelos nomes que o backend declara, montado do que `ListSecrets` e
`GetUpstream` já devolvem.

### 2. Uma visão global pequena, para o que não é de um backend só

Um segredo compartilhado por vários backends, ou órfão (no cofre sem entrada que
o declare, ou declarado sem valor), aparece numa visão global pequena na mesma
aba — com o aviso de "N faltando" que o operador precisa antes de um `redial`.
Não é uma aba; é um bloco secundário.

### 3. Nada do isolamento do cofre muda (de `0050` §2, reafirmado)

- **O valor nunca é devolvido** (`ListSecrets` só dá nomes e presença); a tela
  mostra presença, não valor.
- **Gravar e apagar são root**, pelo socket de contas (`0040` §1): o valor entra
  uma vez, não é devolvido, registrado nem logado, e o `sops` cifra/decifra pela
  entrada e saída padrão, sem o claro tocar o disco.
- A linha de trilha leva o **nome**, nunca o valor (`0050` §2).
- Sem `console_manages` e sem o socket de contas, o bloco de segredos não
  aparece, como hoje (`0050` §1).

## Consequências

- "Esta API tem o que precisa?" é respondido numa página só.
- O caminho de código e os portões do cofre são os mesmos de `0050`; esta ADR só
  reposiciona o que a tela desenha. O isolamento do cofre (fitness function de
  `0001`: nada fora do vault lê um valor) não é afetado — a tela nunca teve o
  valor e continua sem tê-lo.
