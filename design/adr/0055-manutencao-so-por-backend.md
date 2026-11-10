# 0055. Manutenção enxuta: só por backend, sem gateway inteiro e sem aviso em todo resultado

**Status:** Accepted — 10 nov 2026. Supersede a parte de **gateway inteiro** da
manutenção de `0041` §6 e as rotas `/v1/maintenance` de `0040`/`0041`. A
manutenção **por backend** de `0041` fica; o que sai é a manutenção do gateway
como um todo e o aviso que ela anexava a todo resultado. Remover rotas é uma
mudança de contrato: ver §Contrato.

## Contexto

`0041` §6 deu duas formas de manutenção: **por backend** (as chamadas àquele
backend recebem um texto honesto sem discar) e **do gateway inteiro** (um bloco
`text` de aviso **acrescentado ao fim de todo resultado** de `tools/call`, mais
o bloco `gateway` do `gatte.status`). O aviso em todo resultado é superfície
larga: toca o caminho quente de cada chamada, não chega a resultado com
`structuredContent` (medido em `0041` §6), e um resultado de upstream — muitas
vezes escrito pelo atacante num SOC — pode imitar o seu texto palavra por
palavra (`0041` §2). O valor operacional dele — avisar que o `serve` vai parar —
é melhor servido pelo anúncio fora de banda que o time já usa.

A manutenção **por backend** não tem esse problema: ela responde só a quem tem a
tool concedida e aprovada, no passo de disponibilidade do `Dispatch`, e é o que o
operador usa ao reiniciar um backend.

## Decisão

### 1. Fica: manutenção por backend

A capacidade por backend de `0041` continua inteira: a linha de manutenção por
nome, o texto honesto de manutenção ao chamador (`0041` §2), o `started_at`/
`until`/`until_passed`/`message` que chegam a analista (`0041` §6), e o estado
`maintenance` no `gatte.status` por backend.

Ela é operada por:

- **CLI** — `upstream maintenance on|off NAME` e `maintenance list` (`0041` §6);
- **um toggle por backend no console**, na página de detalhe do "MCP server /
  API" (`0051`): estado, desde, e ligar/desligar com CSRF (`0041` §6, front do
  Gatte por backend).

### 2. Sai: manutenção do gateway inteiro e o aviso em todo resultado

- O **aviso de manutenção do gateway acrescentado a todo resultado** (`0041` §6)
  é removido: nenhum resultado de `tools/call` leva mais esse bloco `text`.
- A **manutenção do gateway como um todo** deixa de existir como alvo: o
  `target` `(gateway)` da tabela de manutenção, o bloco `gateway` de manutenção
  no `gatte.status` e os comandos `maintenance on|off` do gateway saem.
- O anúncio de parada do `serve` (atualização de binário, reinício de host)
  passa a ser fora de banda (o canal que o time já usa para avisar o SOC), não
  uma superfície do gateway.

### 3. Restrições que não se cruzam

- A manutenção por backend continua sendo **aviso, não controle**: falha de
  leitura é "sem manutenção", logada (`0041` §6); o `Reconcile` segue discando.
- `until` continua **previsão, não prazo**: não expira sozinho (`0041` §6).
- `set_by`/`set_at` continuam **nunca** chegando a analista (`0041` §6).

## Contrato

Por `0040` §7, **dentro de `/v1` só entram mudanças aditivas; remover, renomear
ou mudar o sentido de um campo ou endpoint é `/v2`**, servido ao lado de `/v1`
por pelo menos uma versão.

Retirar `GET /v1/maintenance`, `POST /v1/maintenance/on` e
`POST /v1/maintenance/off` (e o alvo `(gateway)`, e o bloco de manutenção do
gateway no `gatte.status`) é uma remoção, **não** aditiva. Então:

- a superfície de manutenção por backend que fica é servida numa forma de `/v2`
  (p.ex. presa ao nome do backend, fora das três rotas `/v1/maintenance`), ao
  lado de `/v1` por ao menos uma versão;
- a feature `maintenance` e o enum `maintenance` do `gatte.status` por backend
  permanecem; o que some é o alvo gateway e seu aviso.

A forma exata das rotas de `/v2` e o plano de convivência `/v1`+`/v2` são
trabalho de M2.1 (BLU-78); esta ADR fixa **o que** sai e que sair é `/v2`, não a
assinatura final.

## Consequências

- O caminho quente de `tools/call` perde um passo (o append do aviso do
  gateway) e uma superfície que um resultado de upstream podia imitar.
- Quem dependia do aviso do gateway em todo resultado passa a depender do
  anúncio fora de banda; a manutenção por backend, que é a usada no dia a dia,
  não muda para o analista.
- A remoção força `/v2`: a implantação roda `/v1` e `/v2` lado a lado por uma
  versão, e um front só chama a forma nova depois de ver a feature no `whoami`
  (`0040` §7).
