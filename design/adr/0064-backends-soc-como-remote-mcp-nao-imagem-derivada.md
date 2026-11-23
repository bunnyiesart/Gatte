# 0064. Os backends do SOC são servidos como `remote` MCP (streamable-HTTP), não por uma imagem derivada

**Status:** Accepted — 23 nov 2026. Reverte a opção A (imagem derivada) que
a issue de produto tinha escolhido para servir os quatro MCPs do SOC. Reaproveita
o transporte `remote` (`0058`) tal como está, sem nenhuma mudança no gateway.
Preserva a decisão da imagem única de **não rodar processo de backend nem
container** (`0049`/`0050`): a imagem publicada não tem Python, não tem runtime
de container e nunca recebe o socket do Docker.

## Contexto

A imagem publicada do Gatte serve só backends REST (`http`/OpenAPI, `0047`).
Os quatro MCPs do SOC — `graylog`, `iris`, `swiss`, `opensearch` — são
servidores MCP nativos em Python (stdio), então `gatte setup import` os pula
com uma linha de motivo: a imagem "não roda processo de backend nem container,
não tem runtime para isso, e nunca recebe o socket do Docker, que entregaria
root no host a qualquer coisa dentro dela".

A issue de produto tinha escolhido a **opção A (imagem derivada)**: empacotar
Python + os quatro MCPs numa segunda imagem por cima da base, e o gateway os
spawna como filhos stdio. Isso funciona, mas tem dois custos que só ficaram
claros depois:

1. **Regride o isolamento.** Os backends passam a rodar no mesmo processo/conta
   que segura a chave do vault (`age`), exatamente a lacuna "um host, uma conta
   de serviço" que o `0003`/`0034` já declaram. A opção A amplia essa lacuna
   para os quatro backends de uma vez.
2. **Desfaz a garantia da imagem** de não rodar processo de backend nem
   container (`0049`/`0050`), que é uma propriedade de segurança afirmada na
   README e no `setup import`.

Investigação de 23 nov 2026 nos quatro servidores: todos são FastMCP e **já
suportam streamable-HTTP de forma nativa** — só fixam stdio no ponto de entrada.

- `swiss`, `opensearch`: `fastmcp>=2` (FastMCP 2.x), `mcp.run()` (stdio por
  default). HTTP nativo via `mcp.run(transport="http", ...)`.
- `graylog`, `iris`: `mcp[cli]>=1.0.0` (FastMCP do SDK oficial),
  `mcp.run(transport="stdio")`. HTTP nativo via `mcp.run(transport="streamable-http")`.

Ou seja: não falta um transporte no Gatte (ele já tem `stdio`, `oci`, `http` e
`remote`), e não é preciso construir uma ponte stdio→HTTP. Falta só cada
servidor **poder escolher o transporte**.

## Decisão

Servir os quatro MCPs do SOC pelo transporte **`remote`** (`0058`), não por uma
imagem derivada.

### 1. Cada servidor do SOC ganha transporte selecionável, stdio por default

Uma mudança mínima no ponto de entrada de cada servidor, atrás de variável de
ambiente, mantendo stdio como comportamento default (o Claude Code local não
muda):

- FastMCP 2.x (`swiss`, `opensearch`): `MCP_TRANSPORT=http` →
  `mcp.run(transport="http", host=..., port=...)`.
- SDK oficial (`graylog`, `iris`): `MCP_TRANSPORT=http` →
  `mcp.run(transport="streamable-http")`.

Sem mudança de tool nem de lógica. Cada servidor continua um repositório
separado; cada um recebe seu próprio PR pequeno.

### 2. Cada backend roda no seu próprio container e é registrado com `remote`

Cada MCP sobe no seu container, em modo HTTP, e o Gatte o alcança por URL com
`gatte remote add NAME -url https://.../mcp`. Isso reaproveita o `remote`
(`0058`) e o menu Add de três vias do console (`0059`) sem código novo no
gateway. As chaves de cada backend ficam no container do backend, isoladas do
processo do gateway — o isolamento que a opção B do produto buscava, mas sem
escrever adaptador novo.

### 3. O endpoint HTTP de cada backend exige um segredo; o Gatte é o único cliente

O endpoint streamable-HTTP de cada backend **não pode ficar aberto na rede**: o
Gatte tem que ser o único cliente. O `remote add` já carrega um bearer/header
ao backend; cada servidor passa a exigir esse token (suporte nativo do FastMCP),
atrás de variável de ambiente, desligado por default para não quebrar o uso
stdio local. O valor do token fica no vault do backend / no ambiente do
container, nunca no registro nem no log.

## Consequências

- A imagem publicada do Gatte **não muda** e mantém a garantia de não rodar
  processo de backend nem container. A opção A (imagem derivada) fica descartada.
- Trabalho é quatro PRs pequenos, um por repositório de servidor (`swiss`,
  `graylog-mcp`, `iris-mcp`, `mcp-opensearch`), não código no Gatte.
- **Fora do alcance deste ADR (lacuna declarada):** a conectividade de rede de
  `graylog`/`iris`/`opensearch` até suas próprias fontes de dados. Isso era
  resolvido por uma VPN que não existe mais; é questão de deploy, ortogonal ao
  transporte. `swiss` alcança APIs públicas e não depende disso.
- Prova antes de abrir mão da opção A: um servidor (`opensearch`) é convertido e
  validado ponta a ponta (HTTP `initialize` + `tools/list`, depois `gatte remote
  add` servindo as tools) antes de os outros três seguirem o mesmo padrão.
