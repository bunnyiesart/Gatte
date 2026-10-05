# 0047. Upstreams REST: dialer http, operações do OpenAPI como tools e uma rota de proxy reverso restrita, com egresso pelo cliente do gateway

**Status:** Proposed — 05 out 2026. Decisão de direção; abre trabalho em
fases (§Fases). Cada fase que tomar uma sub-decisão significativa ganha seu
próprio ADR, como manda o `AGENTS.md` §6.

**Revisão de 05 out 2026 (pós-revisão adversarial contra o código):** a
direção segue de pé, mas várias afirmações que sustentavam o texto eram
falsas contra o código atual e foram corrigidas aqui antes de abrir as
fases. Em resumo: a rota de proxy **passa a ser roteada por `Dispatch`** em
vez de ser um segundo caminho de chamada que ignora kill switch, suspensão,
concorrência e quota (§7); a resposta HTTP proxiada **não** é higienizável
por `scrubResult` e ganha um `ModifyResponse` próprio (§5, §7); o esquema
de auth e o conjunto de operações **entram na assinatura e são persistidos**
(§1, §3, §4) — isto é, sim, um campo novo no modelo de dados (Contexto); e
o `InputSchema` gerado preserva a **localização** de cada parâmetro (§2, §3).

## Contexto

Os quatro backends de hoje são servidores MCP que o gateway sobe como
processo filho (`stdio`) ou contêiner (`oci`): o egresso deles é do processo,
e o `0033` o delega ao firewall do host. O time quer registrar também uma
**API REST pura** como upstream — por exemplo `abuseipdb` — sem escrever um
servidor MCP para ela, com dois objetivos:

1. **O analista nunca toca a API real nem a credencial.** O gateway serve uma
   rota própria (`gatte/<nome>/...`), injeta a URL-base e a chave do lado do
   servidor e devolve a resposta já higienizada. É o mesmo isolamento
   estrutural de credencial que o `AGENTS.md` §2 descreve (a `access.Identity`
   não carrega token; o segredo entra só na borda da chamada), agora numa
   requisição HTTP de saída em vez de no ambiente de um processo filho.
2. **Gerar um MCP automaticamente sobre aquela API**, uma tool por operação,
   para que a mesma API também seja chamável como tools pelo Claude Code.

O código já foi construído para este dia. `internal/registry/registry.go:65`
declara `TransportHTTP = "http"` e a entrada tem o campo `URL`
(`registry.go:86-93`), hoje **recusados de propósito** em `Validate`
(`registry.go:202`, rastreado como GAB-19), com o comentário de que "o dia em
que um dialer http existir é um dialer chegando, não uma mudança de schema". A
CLI já tem `-transport http` e `-url` (`cmd/mcp-gateway/upstream.go:290,293`),
recusados só pela `Validate`. O que falta é um dialer, a geração de tools, a
injeção de credencial por cabeçalho, o egresso e a rota servida.

**O schema, porém, cresce — ao contrário do que a versão anterior deste ADR
afirmava.** O transporte e a `URL` já existem, mas o esquema de auth
(§5) e o **conjunto de operações congelado** (§3) precisam ser *persistidos*
na entrada e *cobertos pela assinatura* (§4): hoje `registry.UpstreamServer`
não tem campo para nenhum dos dois, e `signer.Canonical` (`signer.go:124`)
assina apenas `Command/URL/Args/Image` e os *nomes* das env. Logo, isto é um
dialer chegando **e** uma pequena migração de modelo de dados, não só um
dialer — ver §3, §4 e a Fase B.

Decisão do dono (05 out 2026): a rota de proxy reverso é **restrita às
operações declaradas no OpenAPI**, não um passthrough cru. O motivo é o eixo
do projeto inteiro — controle por operação (quarentena por tool, definições
assinadas) e o canal de exfiltração que a própria pesquisa nomeia (um agente
que lê um IOC e faz POST do caso para um endpoint público). Um passthrough cru
entregaria todo path e método da API ao agente e apagaria esse controle.

**Restringir às operações declaradas não fecha, por si, o canal de
exfiltração.** A operação de exfil (o `POST /submit` de um `urlscan`,
`virustotal`, `abuseipdb` e afins) **é** uma operação declarada — §3 a gera
como tool normal, sem distinguir leitura de escrita. O controle de fato é
tratar uma tool gerada de **método HTTP não-seguro** (ou cuja `requestBody`
carrega dado do chamador para fora) como superfície de exfil: *default-deny* —
em quarentena até aprovação explícita **e** atrás de um papel distinto do de
leitura — e não dissolvida na quarentena genérica por tool (ver §3).

## Decisão

Uma API REST registrada tem **um conjunto de operações** (derivado do
OpenAPI) e **dois front-ends sobre esse mesmo conjunto**: as tools MCP
geradas e a rota de proxy reverso. Um registro, uma aprovação de quarentena,
uma trilha, duas superfícies de consumo. Tudo abaixo cai sobre esse conjunto
único, e ambos os front-ends passam pelo **mesmo** caminho autoritativo de
chamada (`gateway.Dispatch`), nunca por um segundo caminho paralelo (§7).

### 1. Transporte `http` de primeira classe

Reabrir o caso `TransportHTTP` em `registry.Validate` (`registry.go:202`):
uma entrada `http` exige `URL`, aceita `EnvVarNames` (os nomes das chaves,
nunca os valores), recusa `Command` e `Image`. GAB-19 fecha. A entrada
assinada passa a descrever `{URL (host + base path), descritor do esquema de
auth, nomes das env, conjunto de operações congelado}` — ver §4. O descritor
de auth e o conjunto de operações são **campos novos** em
`registry.UpstreamServer`, migrados junto com o resto dos schemas por
`openStore` (`AGENTS.md` §2); a Fase A já introduz o descritor de auth (a
injeção do §5 não é demonstrável sem ele), e a Fase B o conjunto de operações.

### 2. Dialer REST — um adaptador novo, sem conexão persistente

Um pacote `internal/gateway/resthttp`, irmão de `internal/gateway/stdio` e
`internal/gateway/oci`, e um `case` em `cmd/mcp-gateway/dialer.go:63`. Ao
contrário de stdio/oci, uma API REST não é uma conexão viva: o `Upstream`
(`internal/gateway/gateway.go:188`) que o dialer entrega é stateless —

- `ListTools` devolve as tools geradas do OpenAPI (§3);
- `CallTool(nome, args)` mapeia a tool → uma requisição HTTP (método + path +
  parâmetros **na localização correta**, ver abaixo), injeta a credencial
  (§5), passa pela allowlist de egresso (§6), executa com
  `Response.call_timeout`/`max_bytes` (`config.go:317,297`) e devolve o corpo
  como resultado da tool.

**Mapeamento de argumentos → requisição preserva a localização do
parâmetro.** OpenAPI identifica um parâmetro pelo par `(name, in)`
(`path`/`query`/`header`/`cookie`) ou pelo `requestBody`; dois parâmetros de
mesmo `name` em locais diferentes são distintos. O `InputSchema` gerado (§3)
carrega essa localização, e `CallTool` a usa para montar a URL e o corpo sem
ambiguidade — sem ela, `id` em path e `id` em query colidiriam numa única
chave e o dialer não saberia onde cada valor vai.

Observação de saúde (ADR-0041): para um upstream http stateless a máquina de
estados de saúde é um `up` constante que nunca transiciona — `markGone`
dispara só em `ErrUpstreamGone` (um stream que termina), que uma API REST
nunca produz. Uma chamada de saída que falha devolve `BackendFailedError`,
mas `gatte.status`/disponibilidade seguem reportando o backend `up`. A Fase A
assume explicitamente **saúde fixa em `up`** para http (a degradação
permitida), ou, se for preciso mais, define um sinal de vivacidade REST
mapeando falha de conexão → `reconnecting`/`down` — mas isso é decisão sua, não
reuso implícito da máquina do 0041.

O `dialTimeRefusal` (`dialer.go:115`) ganha a validação de pré-registro do
transporte http (URL bem-formada, host na allowlist, esquema de auth
conhecido), para que uma entrada que o `serve` recusaria seja recusada já no
`register`/`sign`.

### 3. OpenAPI → tools, no registro

No `upstream register -transport http`, o operador aponta a spec OpenAPI
(arquivo ou URL na allowlist). O gateway gera **uma tool por operação**:

- **`name`** derivado do `operationId` de forma **determinística, única e
  legal**. `validToolName` (`endpoint.go:310`) impõe `^[A-Za-z0-9_-]{1,64}$`
  (o ponto é `NameSeparator`), e `routesFor` descarta **as duas** cópias em
  qualquer colisão de nome dentro do upstream. Logo: sanear o `operationId`,
  anexar um hash curto de `método+path` em colisão ou estouro de comprimento,
  rodar `validToolName` **no momento do `register`** e **falhar o registro em
  alto e bom som** para qualquer operação que não consiga nome único e legal —
  nunca descobrir isso como falha silenciosa por-tool no connect. Operação sem
  `operationId` recebe um nome derivado de `método+path` pela mesma regra.
- **`description`** do `summary`/`description`.
- **`InputSchema`** montado de `parameters` + o schema do `requestBody`, com
  **a localização de cada parâmetro preservada** — ou namespaceando cada
  propriedade (`path_id`/`query_id`/`body_id`), ou por uma anotação
  `x-gatte-param-location` *dentro* dos bytes hasheados do `InputSchema`. A
  localização não pode ficar fora dos bytes assinados/fingerprintados (§2).
  O gerador **resolve `$ref` contra os `components` da spec congelada** e
  achata `allOf`/`oneOf`/`anyOf`, embrulhando o corpo sob
  `{"type":"object","properties":{...}}`: `validateSchema` exige um
  `type:object` de topo (um corpo que seja `$ref`/`allOf` cru é recusado na
  descoberta) e o SDK MCP pula qualquer tool com `$ref` pendente. Como a
  quarentena hasheia os bytes crus sem canonicalização, define-se uma **forma
  canônica de bytes** do `InputSchema` (ordenação de chaves, `$ref` resolvido)
  para que inline-vs-ref não vire, por acidente, uma impressão digital
  diferente.

Essas definições **entram na entrada assinada** e cada tool gerada passa pela
**quarentena** existente (SHA-256 sobre `name+description+schema`, `pending`
até o operador aprovar) — idêntico ao controle por tool de todo o resto. Uma
tool de **método não-seguro** entra em quarentena com *default-deny* e num
papel distinto do de leitura (ver Contexto). Reaproveita
`httpapi.registerTools` (`internal/gateway/httpapi/httpapi.go:829`) e
`Dispatch` (`internal/gateway/endpoint.go:2130`) sem ramo novo: para o
servidor MCP, uma tool REST é só uma tool cujo upstream é um
`resthttp.Upstream`.

O **conjunto de operações congelado é persistido** na entrada (`registry.
UpstreamServer` ganha o campo; §1) e sobrevive a restart — re-buscar é
proibido sem `upstream update`. A spec é **congelada no momento da
assinatura**. Uma spec remota pode mudar embaixo; re-buscar é um
`upstream update` explícito → novas tools → nova quarentena → nova
assinatura. Nunca uma re-leitura silenciosa.

### 4. Assinatura cobre a URL, o esquema de auth e o conjunto de operações (canonical v3)

A forma canônica de hoje cobre `Command/URL + Args + nomes das env`, exclui
valores de segredo (`internal/signer/signer.go:124`, tags `...canonical/v1` e
`...v2-image`). Uma entrada http assina, numa **tag canônica nova
(`v3-http`)** em `signer.go:64`:

- o **host E o base path** da URL (ver §6 sobre por que o base path entra);
- um **digest do conjunto de operações congelado** (§3);
- o **descritor do esquema de auth** — `kind` (bearer/header/query) + o nome
  do cabeçalho ou parâmetro. É ele que decide **onde** a credencial viva é
  injetada (§5); fora da assinatura, trocar `X-API-Key` por um parâmetro de
  query seria edição não assinada que muda o destino do segredo.

Senão, trocar o destino, o conjunto de tools ou o ponto de injeção seria
edição não assinada. É uma sub-decisão própria (ADR na Fase B). O **valor** da
chave continua fora da assinatura: rotação nunca quebra a assinatura, como no
resto (`AGENTS.md` §2, Definition Signer). O campo do descritor de auth e o do
conjunto de operações são adicionados a `UpstreamServer` (§1) e roteados por
`Validate`/`Canonical`.

### 5. Injeção de credencial por cabeçalho — mecanismo novo, máquina reusada

A injeção de hoje é ambiente de processo filho (`resolveEnv`,
`endpoint.go:1915`). REST precisa de injeção **na requisição de saída**:
`Authorization: Bearer <chave>`, `X-API-Key: <chave>` ou um parâmetro de
query, conforme o **descritor de auth assinado** (§4, derivado das
`securitySchemes` do OpenAPI ou do `register`). Reusa, sem copiar plaintext
para lugar nenhum: `vault.Provider.Resolve` (`internal/vault/vault.go:125`) e
o registro de digests `rememberCredentials` (`endpoint.go:4016`).

**A higienização da resposta não é `scrubResult`.** `scrubResult`
(`endpoint.go:2377`) tem assinatura `(ctx, upstream, Result)` e reescreve só
`res.Content`/`res.StructuredContent` de um `Result` MCP já parseado; não tem
caminho para cabeçalhos HTTP e desiste de corpo não-JSON. Um `ReverseProxy`
transmite status, **todos os cabeçalhos** e corpo crus do upstream direto ao
analista — uma credencial refletida num `Location` 3xx, num eco `X-API-Key` ou
num `Set-Cookie` chegaria intacta. Logo, em vez de `scrubResult`, um hook
`ModifyResponse` que: (a) bufferiza sob `Response.max_bytes`, (b) mascara os
valores da credencial no corpo **e nos cabeçalhos** (re-resolvendo os digests
de `rememberCredentials`), (c) recusa/trunca acima do teto. O analista recebe
a resposta higienizada; a chave só existe na requisição de saída. O mesmo hook
serve a tool MCP (sobre o `Result`) e o proxy (sobre a resposta HTTP), para
paridade com o `0014`.

### 6. Egresso pelo cliente do gateway

Com REST **o gateway é o cliente HTTP**: ele disca um `host:porta` conhecido,
tirado da URL assinada. A allowlist vira "o conjunto dos hosts das URLs REST
registradas", imposta no `http.Client` do `resthttp`. A guarda de egresso:

- recusa qualquer host fora da allowlist;
- recusa redirect para host fora da allowlist;
- recusa IP privado, `169.254.0.0/16` e loopback **pelo IP resolvido**, não
  pelo nome — a checagem roda em `net.Dialer.Control` (ou resolve uma vez e
  disca o IP literal), para fechar DNS-rebind/TOCTOU: um host cuja segunda
  resolução vira link-local não pode escapar porque a allowlist olhou a
  string e o dial re-resolveu. A URL `servers` do OpenAPI e qualquer host que
  a spec sugira são **entrada não confiável**; o destino é o host registrado.
  Um host whose-rebind-para-link-local entra no harness de aceite da Fase A.

**`servers[].url` não é descartado inteiro.** A versão anterior mandava
desconfiar de `servers[].url` e ficar só com o host, mas isso joga fora o
**base path** ao qual todo path de operação é relativo (o `/api/v2` do
`abuseipdb` → `/check` gerado dá 404). Na hora do registro: ficar só com o
**host** sob a regra de SSRF/allowlist, mas exigir que a URL registrada (ou o
gerador) **dobre o base path** para dentro; definir comportamento para
múltiplas entradas `servers[]` e para templating de variáveis de servidor. A
URL assinada (`v3-http`, §4) inclui o base path, para ficar dentro da
assinatura.

Esta é a precisão por-entrada que o `0033` havia adiado **para o novo
transporte http, onde o gateway é o cliente**. Ela **não** fecha o passo
`allow_hosts`/CONNECT-SNI do `0033`: aquele passo era sobre conter o egresso
de backends **stdio/oci** que fazem suas próprias conexões de saída pela uid
compartilhada — segue aberto. Aqui só vale quando o próprio gateway é o
cliente HTTP.

**Não casa com `entryNetwork`.** `entryNetwork` (`dialer.go:138`) devolve a
constante `"host"` para todo transporte não-OCI — nunca `host:porta` — e
`"host"`, no `0033` §3, mapeia para backend stdio: semanticamente errado para
o firewall, e `ResolveNetwork(entry.Args)` é vazio para http. O egresso http é
decisão própria da **Fase D**: ou dar a `entryNetwork` um ramo http explícito
devolvendo um tipo nomeado novo (ex. `http:<host:port>` derivado de
`entry.URL`) e estender o vocabulário do `0033` §3 e o verificador de
implantação, ou manter `network="host"` e dizer claramente que o firewall do
host trata estes upstreams como qualquer egresso da uid compartilhada.

### 7. A rota de proxy reverso, restrita às operações (escolha do dono)

Hoje `serve.go:582` entrega `httpapi.Handler` direto, sem mux. Introduzir um
`http.ServeMux` ali. **A regra do mux é explícita:** o segmento reservado
`gatte/` roteia para o proxy (`gatte/<nome>/...`); todo o resto vai para
`httpapi.Handler`; os `metadataPaths` **não** podem cair sob esse prefixo.
Usa-se `gatte/<nome>/...` de forma consistente — o `gatte` reservado é
à-prova-de-colisão porque é nome de upstream reservado — e **não** `/<nome>/...`
na raiz, onde um nome de upstream arbitrário poderia sombrear o endpoint MCP.

**O proxy não é um irmão de `Dispatch`; ele passa por `Dispatch`.** O caminho
autoritativo `gateway.Dispatch` (`endpoint.go:2130`) aplica quatro portões que
um segundo caminho de chamada não pode pular: `checkBlock` (kill switch,
`:2144`, ADR-0031), `isSuspended` (`:2154`, ADR-0020), `slots.acquire`
(concorrência por analista, `:2206`, ADR-0035) e `quota.Admit` (quota por
analista, `:2237`, ADR-0030 — "o único lugar onde pode ir"). A operação casada
é **canalizada por `gateway.Dispatch`** como uma tool namespaceada sintetizada,
com o `ReverseProxy` virando o *transporte* sob `resthttp.CallTool`. O handler
de proxy:

- autentica pelo **mesmo** caminho Authelia/OIDC (`httpapi.authenticate`,
  `httpapi.go:456`);
- casa `método+path` de entrada contra o **conjunto de operações aprovadas**
  de `<nome>` que o papel do chamador permite — uma operação em quarentena ou
  fora do papel **não** é roteável; responde 404/403 a qualquer path/método
  fora do conjunto aprovado — não é passthrough;
- **grava a linha de trilha `OutcomeAllowed` e bloqueia no sucesso dela ANTES
  de qualquer byte chegar ao upstream** — o invariante record-then-forward do
  `Dispatch` ("refusing unauditable call", `endpoint.go:2263-2267`, o exato
  comportamento que o `AGENTS.md` fixa sob a enxurrada ADR-0027). O
  `Director`/`Rewrite` do `ReverseProxy` não tem retorno de aborto e o
  `ModifyResponse` só roda depois que o upstream já recebeu a chamada; logo o
  proxy **recusa pela mesma via "unauditable call"** se a trilha não puder ser
  escrita primeiro, em vez de encaminhar e auditar depois;
- injeta a credencial (§5), impõe a allowlist de egresso (§6), encaminha
  (`net/http/httputil.ReverseProxy`) e higieniza a resposta com o
  `ModifyResponse` do §5 (não `scrubResult`).

Proxy e tools MCP são, assim, dois front-ends sobre o mesmo conjunto de
operações, ambos por `Dispatch`: a mesma aprovação, a mesma trilha, os mesmos
portões de bloqueio/suspensão/concorrência/quota valem para os dois.

## Fases

Ordem de dependência; cada uma termina num artefato verificável e as que
tomam sub-decisão ganham ADR próprio.

- **A — transporte http chamável.** Reabrir `Validate` (§1), dialer `resthttp`
  (§2) com mapeamento manual de operação (sem OpenAPI ainda), **campo de
  descritor de auth na entrada** (§1/§4) e injeção por cabeçalho (§5),
  `ModifyResponse` de higienização (§5), allowlist de egresso + guarda de SSRF
  no IP resolvido (§6). Fim: um upstream REST aprovado é chamável como tools
  MCP. Harness: um mock REST em `lab/`, incluindo o teste de DNS-rebind do §6.
- **B — OpenAPI → tools + assinatura v3.** Ingestão da spec (§3) com resolução
  de `$ref` e derivação de nome colisão-segura, **persistência do conjunto de
  operações congelado** (§3/§1), `canonical/v3-http` cobrindo URL+base path,
  descritor de auth e digest de operações (§4), quarentena das tools geradas
  com default-deny para métodos não-seguros. ADR próprio para a v3.
- **C — rota de proxy reverso restrita.** O mux em `serve.go:582` com a regra
  de prefixo `gatte/` (§7) e o handler que **roteia por `Dispatch`** (§7). ADR
  próprio para a superfície de ingresso nova.
- **D — endurecimento e docs.** Decisão do egresso http em `entryNetwork`/mapa
  do `0033` (§6), **verificador de egresso que lê o host da URL assinada e
  afirma igualdade com o mapa de implantação** (não só presença), `README`
  (Security model), `config.example.toml`.

## Consequências

- **O primeiro caminho HTTP de saída do gateway para um backend** nasce aqui
  (hoje só há clientes de saída para o IdP e o socket admin — `oidc.go:222`,
  `check.go:171`, `pkg/adminapi/client.go:73`). Toda a superfície de SSRF e de
  egresso que isso abre é tratada no §6 e é condição de aceite da Fase A.
- **Há um campo novo no modelo de dados.** `UpstreamServer` ganha o descritor
  de auth e o conjunto de operações congelado, com migração em `openStore`
  (§1, §3) e codificação canônica própria em `signer.go` (§4). Não é só "um
  dialer chegando".
- **Dois front-ends, um caminho de chamada.** O proxy não ganha portões
  próprios: ele passa por `Dispatch` (§7). Não há segundo lugar para manter
  kill switch, suspensão, concorrência, quota e o invariante record-then-forward.
- **APIs com OAuth, não com chave estática, são sub-decisão posterior.** O
  `AGENTS.md` §2 (token-passthrough) exige que, para uma API OAuth, o gateway
  **cunhe o próprio token** (client-credentials), nunca repasse o do analista.
  O primeiro alvo (`abuseipdb` e afins) é chave estática; OAuth entra num ADR
  quando for preciso.
- **O conjunto de operações é o que a spec declara no momento da assinatura.**
  Drift de spec remota não muda nada servido sem um `update` + reassinatura
  explícitos. Uma API sem OpenAPI fica no mapeamento manual da Fase A até
  ganhar spec.
- **Uma única fonte de destino para o egresso http.** A allowlist em binário
  (o `DialContext` sobre o host da URL assinada) e o mapa de firewall da
  implantação precisam **casar**, senão um `upstream update` que move o host
  atualiza um e deixa o outro velho (dial passa, firewall derruba em silêncio).
  O verificador da Fase D lê o host da URL **assinada** e afirma que o
  `host:porta` do mapa é igual a ele — a URL assinada é a fonte única; alargar
  o destino continua sendo diff assinado, como no `0033`.
- **A rota de proxy não higieniza como uma tool MCP sem ajuda.** `scrubResult`
  não alcança cabeçalhos HTTP; o `ModifyResponse` do §5 é o que mascara
  credencial em corpo e cabeçalho da resposta proxiada.
- **Não cobre, e não se afirma coberto:** paginação e APIs com estado,
  WebSocket/streaming além do teto de `max_bytes`, o passo `allow_hosts`/
  CONNECT-SNI do `0033` para backends stdio/oci na uid compartilhada (segue
  aberto — §6), saúde REST além de `up` fixo (§2), e injeção de prompt via
  resultado (continua aberta, como no `0014`) — uma resposta de API REST é
  texto de terceiro igual à de um backend MCP.
