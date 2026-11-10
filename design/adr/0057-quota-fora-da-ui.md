# 0057. A quota sai da UI; o controle continua ativo no servidor

**Status:** Accepted — 10 nov 2026. Supersede a parte da página/visão de quota do
console de `0040` (o `QuotaUsage` desenhado na tela). O controle de quota de
`0030` **não muda**: ele continua ativo no servidor. O que sai é a **tela**.

## Contexto

O console tinha uma visão de quota (`QuotaUsage`, rota `/quota`, `0040`). Mas a
quota (`0030`) é um limite por analista por conta de terceiro que o gateway
aplica a cada chamada; não é algo que o operador **opere** pela tela — não há
botão de "mudar a quota" ali (orçamentos vêm da configuração, `0030`/`0044`). Uma
tela só de leitura de contadores duplica o que o `gatte.status` e o CLI já
reportam.

## Decisão

### 1. Sai: a página/visão de quota do console

A aba/visão de quota e a rota `/quota` saem da tela. O console não desenha mais
contadores de quota.

### 2. Fica, intacto: o controle de quota no servidor

O controle de `0030` **continua ativo**: a contagem por analista por conta de
terceiro, a cobertura (`uncounted`) que o `Reconcile` exige para servir (`0041`
§1), e a recusa quando o orçamento estoura, tudo como está. **Nada de segurança
ou de aplicação muda** — isto é remoção de superfície de leitura, não do
controle.

### 3. Visível por CLI e `gatte.status`

O uso de quota continua legível pelo CLI (o `-json` de `quota usage`, `0030`) e,
para o analista, pelo que o `gatte.status` já reporta do estado dos seus
backends (`0041` §5). O operador que precisa dos contadores usa o CLI.

## Contrato

Se a implementação optar por remover `QuotaUsage`/`GET /v1/...quota...` do
contrato HTTP, isso é remoção de endpoint, logo `/v2` por `0040` §7 (ao lado de
`/v1` por ao menos uma versão). Manter o endpoint servido e apenas **não
desenhá-lo** no console é aditivo-neutro e não força `/v2`. A escolha é de M2.2;
esta ADR fixa que a **tela** sai e o **controle** fica.

## Consequências

- O console encolhe uma aba sem perder nenhum controle: a quota segue aplicada.
- Quem precisa dos números usa o CLI ou lê o estado pelo `gatte.status`; não há
  mais uma tela só de leitura competindo com eles.
- A fatia M2.2 remove a nav/página e confirma, por teste, que o controle de
  `0030` continua ativo e visível por CLI/`gatte.status`.
