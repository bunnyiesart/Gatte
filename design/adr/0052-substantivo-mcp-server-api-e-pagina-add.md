# 0052. O substantivo "MCP server / API" e a página de adicionar

**Status:** Accepted — 10 nov 2026. Detalha a aba "MCP Servers / APIs" de
`0051`. Anota `0047`/`0048` (o transporte http gerado de OpenAPI) e `0050` §2/§5
(registrar e assinar pelo console); não muda nenhuma regra deles.

## Contexto

Um upstream REST registrado por OpenAPI (`0047`, `0048`) **vira tools MCP**: o
gateway gera uma tool por operação do documento. Para o operador, "upstream" e
"backend" são palavras do código; o que ele vê e adiciona é uma API que passa a
ser servida como MCP. A tela precisa de um substantivo que diga isso sem ensinar
jargão interno, e precisa de um lugar para adicionar sem violar o zero-JS
(`0036`).

Registrar stdio e oci continua fora da tela por decisão registrada (`0050` §2,
"Não cobre"; `0034`): stdio com credencial exige `allow_credentialed_stdio`, e
oci é o caminho isolado — os dois são CLI.

## Decisão

### 1. O substantivo é "MCP server / API"

A lista e o detalhe chamam cada backend de **"MCP server / API"**. O botão de
adicionar diz **"REST API / OpenAPI → generates MCP tools"**, que nomeia a
entrada (um OpenAPI) e o efeito (tools MCP) numa linha. É rótulo de tela; não
muda nenhum nome no fio, no contrato nem no banco.

### 2. Adicionar é uma sub-página, não um modal

Adicionar abre `/servers/new` (zero-JS, `0036`): um formulário que recebe o
OpenAPI por URL, por texto colado ou por upload — o mesmo caminho do `upstream
register -transport http` (`0050` §2), com a mesma ingestão, as mesmas recusas e
o mesmo relatório, e sob a guarda de egresso do adapter quando a URL é buscada
(`0048` §6). Só http: **stdio e oci continuam só no CLI** (`0050` §2, `0034`), e
a página diz isso em vez de oferecer um caminho que recusaria.

### 3. Restrições que não se cruzam (de `0047`/`0048`/`0050`)

- **Assinar é um segundo clique atestante** (`0050` §5): registrar **não**
  assina. A página de resultado mostra a URL, onde a credencial é injetada, se o
  descritor de auth foi derivado do documento e cada operação com método, path e
  classe; só ali há o botão de assinar. Nunca assinar-no-registro.
- **As tools geradas nascem pendentes** e são invisíveis e não-chamáveis até
  aprovação humana por fingerprint (`0036`, `0032`). A aprovação vive no detalhe
  do backend (`0051`).
- **Tool sensível** (método não-GET, classe `sensitive` de `0048`) exige `clear`
  **e** um papel `non_read` que a nomeie (`0048` §5); o console não contorna
  esse portão.
- **Desregistrar** pede o nome digitado, porque apaga as aprovações junto
  (`0050` §2).

## Consequências

- O operador adiciona uma API pela tela e entende, pelo rótulo, que ela vira
  tools MCP que ainda precisam de aprovação.
- stdio/oci permanecem uma decisão consciente de CLI; a tela não finge
  cobri-los.
- Nada de novo no contrato: é o caminho http de `0050`, re-rotulado e com a
  página de adicionar separada. A assinatura e a quarentena seguem intactas.
