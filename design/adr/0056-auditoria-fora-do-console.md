# 0056. A auditoria sai do console: ela vive no SIEM

**Status:** Accepted — 10 nov 2026. Supersede a parte da página de auditoria do
console de `0036`/`0040` (listar e paginar a trilha pela tela). A trilha, o
encadeamento por hash e o envio ao SIEM de `0015`/`0017`/`0029` **não mudam**; o
que sai é a **tela** de auditoria.

## Contexto

O console tinha uma página de auditoria: listar a trilha com filtros, paginação
e um limite de 5000 (`0036` §3.7, `0040`). Mas a trilha já é enviada ao SIEM —
uma linha JSONL por registro para um shipper (`0017`), e opcionalmente uma cópia
GELF (`0029`) — e é lá que ela se pesquisa, correlaciona e alerta. Reimplementar
busca e paginação de trilha no console é construir, pior, o que o Graylog/Wazuh
já faz, e espalha a verificação por dois lugares.

O que **não** vive no SIEM é a verificação de integridade da cadeia: comparar a
cabeça que o Gatte escreveu com a cabeça que o SIEM indexou é o que detecta
edição do arquivo do banco (`0017`), e a ausência de batimento é o que detecta
shipper morto (`0021`). Essas são verificações, não navegação.

## Decisão

### 1. Sai: a página de auditoria do console

A aba Audit, a lista/filtros/paginação da trilha e o limite de 5000 saem da tela.
Para ler a trilha, usa-se o SIEM.

### 2. Fica: a verificação de integridade, por CLI e agendada

- A **verificação da cadeia** continua existindo pelo CLI (`audit verify`,
  `-expect-head`) e por uma checagem **agendada** que compara a cabeça do Gatte
  com a cabeça que o SIEM recebeu (sobre `deploy/gatte-anchor-verify.sh`,
  `0017`). Essa é a parte com valor de segurança; ela não é uma tela.
- A **ausência de batimento** (`0021`) continua sendo o alerta de "as linhas
  pararam de chegar" no SIEM.

### 3. Restrições que não se cruzam (de `0015`/`0017`/`0021`/`0029`)

- O **encadeamento por hash** e a gravação da trilha não mudam (`0015`).
- Pelo menos **um caminho de envio fiel ao JSONL** é mantido (`0017`): o shipper
  que lê o arquivo local. A âncora externa (a cabeça esperada) **não** é roteada
  pelo GELF (`0029`) — uma âncora guardada pelo mesmo caminho que ela
  autentica não é âncora (`0010`, aplicado à cauda em `0017`).
- O batimento e a sua ausência ficam no **mesmo canal** da trilha (`0021`).

## Consequências

- A trilha se pesquisa onde ela já é indexada e correlacionada; o console não
  compete com o SIEM.
- A detecção que importa — edição do banco, shipper morto — continua existindo,
  como CLI e checagem agendada, não como página.
- M3 (BLU-74) executa isto em ordem: primeiro a checagem de cabeça agendada
  (M3.1), depois o decoder/ruleset de Wazuh (M3.2), e por fim remover a página
  do console (M3.3), coordenado com a limpeza de nav de M1.6. Esta ADR fixa a
  decisão; a remoção da página é a fatia M3.3.
