# 0047. Upstreams REST: dialer http, operações do OpenAPI como tools e uma rota de proxy reverso restrita, com egresso pelo cliente do gateway

**Status:** Proposed — 05 out 2026. Decisão de direção; abre trabalho em
fases (§Fases). Cada fase que tomar uma sub-decisão significativa ganha seu
próprio ADR, como manda o `AGENTS.md` §6.

**Revisão de 05 out 2026 (duas passagens de revisão adversarial contra o
código).** A direção segue de pé; o texto foi corrigido duas vezes antes de
abrir as fases, porque a primeira correção introduziu uma incoerência de tipo.
Estado atual:

- **Os dois front-ends (tools MCP e proxy) passam pelo mesmo `gateway.Dispatch`**
  — kill switch, suspensão, concorrência, quota e record-then-forward valem
  para ambos (§7).
- **Não há `ReverseProxy` nem `ModifyResponse`.** `Upstream.CallTool` devolve
  um `gateway.Result` sem cabeçalhos HTTP (`gateway.go:153-170,195`) e um
  `httputil.ReverseProxy` escreve direto no `ResponseWriter` e não devolve
  nada — os dois não compõem. O `resthttp.CallTool` faz um round-trip
  bufferizado e **serializa status + cabeçalhos + corpo dentro do
  `Result.Content`**; com isso a resposta flui por `Dispatch` como qualquer
  tool e o **`scrubResult` que já existe** (`endpoint.go:2342,2377`) mascara a
  credencial em todo o blob, cabeçalhos inclusive — sem segundo caminho e sem
  hook novo (§5, §7).
- **O esquema de auth e a URL completa entram na assinatura já na Fase A**, no
  mesmo momento em que passam a dirigir a injeção; o digest do conjunto de
  operações entra na Fase B, quando o conjunto passa a existir (§1, §4, Fases).
- **`UpstreamServer` ganha campos novos** (descritor de auth, e na Fase B o
  conjunto de operações congelado) — é uma pequena migração de modelo de
  dados, não "só um dialer chegando" (Contexto, §1, §3).
- **O `InputSchema` gerado preserva a localização de cada parâmetro por
  namespacing** (não por anotação sobre um objeto plano, que ainda colidiria)
  (§2, §3).

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
afirmava.** O transporte e a `URL` já existem, mas o **descritor do esquema de
auth** (§5) e o **conjunto de operações congelado** (§3) precisam ser
*persistidos* na entrada e *cobertos pela assinatura* (§4): hoje
`registry.UpstreamServer` não tem campo para nenhum dos dois, e
`signer.Canonical` (`signer.go:124`) assina `Name`, `Transport`, `Command`,
`URL`, `Image` e os *nomes* das env — não um descritor de auth nem um conjunto
de operações. Logo, isto é um dialer chegando **e** uma pequena migração de
modelo de dados — ver §3, §4 e as Fases A/B.

Decisão do dono (05 out 2026): a rota de proxy reverso é **restrita às
operações declaradas no OpenAPI**, não um passthrough cru. O motivo é o eixo
do projeto inteiro — controle por operação (quarentena por tool, definições
assinadas) e o canal de exfiltração que a própria pesquisa nomeia (um agente
que lê um IOC e faz POST do caso para um endpoint público). Um passthrough cru
entregaria todo path e método da API ao agente e apagaria esse controle.

**Restringir às operações declaradas não fecha, por si, o canal de
exfiltração**, e o controle precisa de mecanismo, não só de disciplina. A
operação de exfil (o `POST /submit` de um `urlscan`, `virustotal`,
`abuseipdb` e afins) **é** uma operação declarada — §3 a gera como tool. O
controle de fato: no momento da geração (§3) cada tool recebe uma **classe de
segurança** derivada do método HTTP (safe/não-safe), gravada como metadado da
tool na entrada assinada. Uma tool de método não-safe nasce **default-deny** —
em estado de quarentena próprio (uma classe nova ao lado de
`pending`/`approved`/`changed`, não a quarentena genérica) que exige aprovação
explícita e concessão a um **papel distinto do de leitura**. A classificação
mora na borda REST/registro; o `internal/access` continua casando por nome de
tool, sem aprender o que é método HTTP (a classe chega como metadado, não como
regra no domínio puro). Ver §3 para onde o acoplamento vive.

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
assinada passa a descrever `{URL completa, descritor do esquema de auth, nomes
das env, classe de segurança por operação, e — na Fase B — conjunto de
operações congelado}` — ver §4. O descritor de auth é um **campo novo** em
`registry.UpstreamServer`, migrado junto com os demais schemas por `openStore`
(`cmd/mcp-gateway/main.go`, `AGENTS.md` §2); a **Fase A já o introduz e já o
assina** (a injeção do §5 não pode dirigir-se por um campo não assinado — ver
§4 e as Fases). O conjunto de operações congelado é outro campo, adicionado na
Fase B (§3).

### 2. Dialer REST — um adaptador novo, sem conexão persistente

Um pacote `internal/gateway/resthttp`, irmão de `internal/gateway/stdio` e
`internal/gateway/oci`, e um `case` em `cmd/mcp-gateway/dialer.go:63`. Ao
contrário de stdio/oci, uma API REST não é uma conexão viva: o `Upstream`
(`internal/gateway/gateway.go:188`) que o dialer entrega é stateless —

- `ListTools` devolve as tools geradas do OpenAPI (§3);
- `CallTool(ctx, nome, args)` mapeia a tool → uma requisição HTTP (método +
  path + parâmetros **na localização correta**, ver abaixo), injeta a
  credencial (§5), passa pela allowlist de egresso (§6), executa com
  `Response.call_timeout`/`max_bytes` (`config.go:317,297`) e **serializa a
  resposta — status, cabeçalhos e corpo — dentro do `gateway.Result`** que a
  interface exige (`CallTool(...) (Result, error)`, `gateway.go:195`;
  `Result` não tem campo de status/cabeçalho HTTP, `gateway.go:153-170`). O
  status não-2xx mapeia em `Result.IsError`; status, cabeçalhos e corpo vão em
  `Result.Content` como um bloco JSON (forma canônica definida na Fase A). É
  assim que a resposta REST atravessa `Dispatch` como qualquer tool — e é
  `Dispatch` quem roda `scrubResult` sobre esse `Result` (§5, §7).

**Mapeamento de argumentos → requisição preserva a localização do
parâmetro.** OpenAPI identifica um parâmetro pelo par `(name, in)`
(`path`/`query`/`header`/`cookie`) ou pelo `requestBody`; dois parâmetros de
mesmo `name` em locais diferentes são distintos. O `InputSchema` gerado (§3)
**namespaceia** cada propriedade por local (`path_id`, `query_id`, `body_id`,
`header_x`), e `CallTool` usa o prefixo para montar URL, query, cabeçalhos e
corpo sem ambiguidade — sem isso, `id` em path e `id` em query colidiriam numa
única chave JSON.

Observação de saúde (ADR-0041): para um upstream http stateless a máquina de
estados de saúde é um `up` constante que nunca transiciona — `markGone`
dispara só em `ErrUpstreamGone` (um stream que termina), que uma API REST
nunca produz. Uma chamada de saída que falha devolve `BackendFailedError`,
mas `gatte.status`/disponibilidade seguem reportando o backend `up`. A Fase A
assume explicitamente **saúde fixa em `up`** para http (a degradação
permitida); se for preciso mais, um sinal de vivacidade REST mapeando falha de
conexão → `reconnecting`/`down` é decisão própria, não reuso implícito da
máquina do 0041.

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
  rodar a regra **no momento do `register`** e **falhar o registro em alto e
  bom som** para qualquer operação sem nome único e legal — nunca descobrir
  isso como falha silenciosa por-tool no connect. Operação sem `operationId`
  usa `método+path`. Como `validToolName` é não-exportado em `internal/gateway`
  e o `register` vive em `cmd/mcp-gateway`, a regra do charset é **exportada de
  um lugar só** (ou `validToolName` passa a exportado), para que `register` e
  `routesFor` não divirjam. As outras recusas por-tool do `routesFor` (schema
  > 64 KiB `endpoint.go:1722`, `validateSchema` `:1726`, `resolveOutputSchema`
  `:1753`, `quarantine.Observe` `:1758`) ou também sobem para o `register`, ou
  ficam explicitamente como recusa por-tool no connect — a decisão é da Fase B,
  mas é tomada, não deixada implícita.
- **`description`** do `summary`/`description`.
- **`InputSchema`** montado de `parameters` + o schema do `requestBody`, com
  **a localização de cada parâmetro preservada por namespacing**
  (`path_id`/`query_id`/`header_x`/`body_id`) — a anotação `x-gatte-param-
  location` sobre um objeto plano **não** basta, porque dois params de mesmo
  `name` ainda colapsariam numa chave. O **nome do cabeçalho/cookie de auth
  injetado é reservado**: um parâmetro `header_*`/`cookie_*` declarado que o
  sombreie é recusado/descartado no registro, para o chamador não sobrescrever
  a credencial do servidor. O gerador **resolve `$ref` contra os `components`
  da spec congelada**; `allOf` funde no mapa de propriedades, mas `oneOf`/
  `anyOf` **preservam a alternância** como irmãos de topo
  (`{"type":"object","oneOf":[...]}`), que `validateSchema` (`endpoint.go:3905`)
  aceita — achatá-los num só `properties` aceitaria corpos que nenhuma
  alternativa aceitava. Um `requestBody` **não-objeto** (array/escalar JSON,
  `application/octet-stream`) ganha uma representação explícita sob a mesma
  regra (ex. `body` único tipado), definida na Fase B. Define-se também uma
  **forma canônica de bytes** do `InputSchema` (ordenação de chaves, `$ref`
  resolvido) porque a quarentena hasheia os bytes crus.
- **Classe de segurança por método** (safe/não-safe), metadado da tool na
  entrada assinada; método não-safe → default-deny em classe de quarentena
  própria + papel distinto (Contexto). O acoplamento mora aqui (geração/
  registro) e no estado de quarentena, nunca no `internal/access`.

Essas definições **entram na entrada assinada** e cada tool gerada passa pela
**quarentena** existente (SHA-256 sobre `name+description+schema`, `pending`
até o operador aprovar) — idêntico ao controle por tool do resto, acrescido da
classe de segurança acima. Reaproveita `httpapi.registerTools`
(`internal/gateway/httpapi/httpapi.go:829`) e `Dispatch`
(`internal/gateway/endpoint.go:2130`) sem ramo novo no caminho de chamada:
para o servidor MCP, uma tool REST é só uma tool cujo upstream é um
`resthttp.Upstream`.

O **conjunto de operações congelado é persistido** na entrada (`registry.
UpstreamServer` ganha o campo na Fase B; §1) e sobrevive a restart — re-buscar
é proibido sem `upstream update`. A spec é **congelada no momento da
assinatura**. Uma spec remota pode mudar embaixo; re-buscar é um
`upstream update` explícito → novas tools → nova quarentena → nova
assinatura. Nunca uma re-leitura silenciosa.

### 4. Assinatura cobre a URL, o esquema de auth e o conjunto de operações (canonical v3)

A forma canônica de hoje assina `Name`, `Transport`, `Command`, a **URL
inteira** (`s.URL`, `signer.go:139`), `Image` e os *nomes* das env, excluindo
valores de segredo (`signer.go:124-160`, tags `...canonical/v1` e
`...v2-image`). Uma entrada http assina, numa **tag canônica nova
(`v3-http`)** em `signer.go:64`, **tudo o que a v1 já assina** (Name,
Transport, EnvVarNames, e a URL) **mais**:

- a **URL completa** — esquema, host, porta E base path (ver §6 sobre o base
  path; a v1 já assina a `s.URL` inteira, então a v3 não pode cobrir *menos*:
  deixar esquema/porta de fora deixaria um downgrade `https→http` ou uma troca
  de porta como edição não assinada, e é a porta que o verificador de egresso
  da Fase D compara);
- o **descritor do esquema de auth** — `kind` (bearer/header/query) + o nome
  do cabeçalho ou parâmetro. É ele que decide **onde** a credencial viva é
  injetada (§5); fora da assinatura, trocar `X-API-Key` por um parâmetro de
  query por escrita direta no banco seria edição não assinada que redireciona
  o segredo e ainda verifica como assinada — o exato ataque que a assinatura
  existe para fechar (modelo de ameaça em `signer.go:255-269`);
- na **Fase B**, um **digest do conjunto de operações congelado** (§3).

É uma sub-decisão própria (ADR na Fase B para o digest de operações; o
descritor de auth e a URL completa já na Fase A, ver Fases). O **valor** da
chave continua fora da assinatura: rotação nunca quebra a assinatura, como no
resto (`AGENTS.md` §2, Definition Signer).

### 5. Injeção de credencial por cabeçalho — mecanismo novo, máquina reusada

A injeção de hoje é ambiente de processo filho (`resolveEnv`,
`endpoint.go:1915`). REST precisa de injeção **na requisição de saída**:
`Authorization: Bearer <chave>`, `X-API-Key: <chave>` ou um parâmetro de
query, conforme o **descritor de auth assinado** (§4, derivado das
`securitySchemes` do OpenAPI ou do `register`). Reusa, sem copiar plaintext
para lugar nenhum: `vault.Provider.Resolve` (`internal/vault/vault.go:125`) e
o registro `rememberCredentials` (`endpoint.go:4016`).

**A higienização da resposta é o `scrubResult` que já existe — não um hook
novo.** Como o `resthttp.CallTool` serializa status, cabeçalhos e corpo dentro
do `Result.Content` (§2), a resposta atravessa `Dispatch`, que roda
`scrubResult(ctx, upstream, res)` incondicionalmente sobre todo `Result`
(`endpoint.go:2342`, definido em `:2377`). `scrubResult` mascara pegando os
**nomes** das credenciais em `g.creds[upstream]` e re-resolvendo o **plaintext**
em `g.vault.Resolve` (`endpoint.go:2379-2404`) — **não** os digests de
`rememberCredentials`, que são HMAC-SHA256 de via única (`endpoint.go:4010-4013`)
e não voltam a plaintext. Como os cabeçalhos agora fazem parte do
`Result.Content`, uma credencial refletida num `Location` 3xx, num eco
`X-API-Key` ou num `Set-Cookie` é mascarada pelo mesmo caminho — **desde que**
o conjunto de renderizações de `scrubResult` ganhe uma forma **URL-decodificada**
(`redact.go:123-156` hoje só tem valor cru, `%q`/`QuoteToASCII` e encoding de
string JSON; um valor percent-encodado num redirect não casaria). Essa extensão
do `scrubResult` (uma renderização a mais) é parte da Fase A.

O caminho da tool MCP (não-proxy) **mantém `scrubResult` inalterado** sobre o
`Result` (`endpoint.go:2342`) — não há hook `ModifyResponse` nele nem seam para
um, e o `0014` continua valendo igual. O analista recebe a resposta
higienizada; a chave só existe na requisição de saída.

### 6. Egresso pelo cliente do gateway

Com REST **o gateway é o cliente HTTP**: ele disca um `host:porta` conhecido,
tirado da URL assinada. A allowlist vira "o conjunto dos hosts das URLs REST
registradas", imposta no `http.Client` do `resthttp`. A guarda de egresso:

- recusa qualquer host fora da allowlist;
- recusa redirect para host fora da allowlist;
- recusa IP privado, `169.254.0.0/16` e loopback **pelo IP resolvido**, não
  pelo nome — a checagem roda em `net.Dialer.Control` (ou resolve uma vez e
  disca o IP literal), para fechar DNS-rebind/TOCTOU: um host cuja segunda
  resolução vira link-local não escapa porque a allowlist olhou a string e o
  dial re-resolveu. A URL `servers` do OpenAPI e qualquer host que a spec
  sugira são **entrada não confiável**; o destino é o host registrado. Um host
  que rebinde para link-local entra no harness de aceite da Fase A.

**`servers[].url` não é descartado inteiro.** Desconfiar de `servers[].url` e
ficar só com o host joga fora o **base path** ao qual todo path de operação é
relativo (o `/api/v2` do `abuseipdb` → `/check` gerado dá 404). Na hora do
registro: ficar só com o **host** sob a regra de SSRF/allowlist, mas exigir que
a URL registrada (ou o gerador) **dobre o base path** para dentro; definir
comportamento para múltiplas entradas `servers[]` e para templating de
variáveis de servidor. A URL assinada (`v3-http`, §4) inclui esquema, host,
porta e base path.

Esta é a precisão por-entrada que o `0033` havia adiado **para o novo
transporte http, onde o gateway é o cliente**. Ela **não** fecha o passo
`allow_hosts`/CONNECT-SNI do `0033`: aquele passo era sobre conter o egresso
de backends **stdio/oci** que fazem suas próprias conexões de saída pela uid
compartilhada — segue aberto. Aqui só vale quando o próprio gateway é o
cliente HTTP.

**Não casa com `entryNetwork`.** `entryNetwork` (`dialer.go:138`) devolve a
constante `stdioNetwork="host"` para todo transporte não-OCI (`dialer.go:140`),
**antes** de chegar ao ramo OCI que chamaria `ResolveNetwork` (`:142`) — ou
seja, `ResolveNetwork` nunca é invocado para http. E `"host"`, no `0033` §3,
mapeia para backend stdio: semanticamente errado para o firewall. O egresso
http é decisão própria da **Fase D**: ou dar a `entryNetwork` um ramo http
explícito devolvendo um tipo nomeado novo (ex. `http:<host:port>` derivado de
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

**O proxy não é um irmão de `Dispatch`; ele passa por `Dispatch`, e não usa
`ReverseProxy`.** O caminho autoritativo `gateway.Dispatch` (`endpoint.go:2130`)
aplica quatro portões que um segundo caminho de chamada não pode pular:
`checkBlock` (kill switch, `:2144`, ADR-0031), `isSuspended` (`:2154`,
ADR-0020), `slots.acquire` (concorrência por analista, `:2206`, ADR-0035) e
`quota.Admit` (quota por analista, `:2237`, ADR-0030 — "o único lugar onde pode
ir"), grava a linha `OutcomeAllowed` **antes** de encaminhar (`:2263-2267`,
"refusing unauditable call") e roda `scrubResult` no retorno (`:2342`). Um
`httputil.ReverseProxy` não compõe com isso: ele escreve status/cabeçalhos/
corpo direto no `ResponseWriter` e não devolve `Result`, enquanto
`Upstream.CallTool` devolve `(Result, error)` sem acesso ao `ResponseWriter`
(`gateway.go:195`). Então o handler de proxy:

- autentica pelo **mesmo** caminho Authelia/OIDC (`httpapi.authenticate`,
  `httpapi.go:456`);
- casa `método+path` de entrada contra o **conjunto de operações aprovadas**
  de `<nome>` que o papel do chamador permite — operação em quarentena, de
  método não-safe não concedido, ou fora do papel **não** é roteável; responde
  404/403 fora do conjunto — não é passthrough;
- traduz a requisição na tool sintetizada correspondente e **chama
  `gateway.Dispatch`** com ela. O round-trip HTTP, a injeção (§5) e a allowlist
  de egresso (§6) acontecem dentro do `resthttp.CallTool`, que serializa a
  resposta num `Result` (§2); `Dispatch` aplica os quatro portões, grava a
  trilha antes de qualquer byte de saída e roda `scrubResult` no `Result`;
- devolve ao analista o `Result` já higienizado, reconstituindo status/
  cabeçalhos/corpo a partir do `Result.Content` serializado.

Assim o record-then-forward não é reimplementado no proxy: é o do `Dispatch`,
porque a chamada do proxy **é** uma chamada do `Dispatch`. Proxy e tools MCP
são dois front-ends sobre o mesmo conjunto de operações, ambos por `Dispatch`:
a mesma aprovação, a mesma trilha, os mesmos portões de bloqueio/suspensão/
concorrência/quota, a mesma higienização.

## Fases

Ordem de dependência; cada uma termina num artefato verificável e as que
tomam sub-decisão ganham ADR próprio.

- **A — transporte http chamável e já assinável com segurança.** Reabrir
  `Validate` (§1); dialer `resthttp` (§2) com mapeamento manual de operação
  (sem OpenAPI ainda) que serializa a resposta HTTP num `Result`; **campo de
  descritor de auth na entrada E cobertura dele + URL completa pela assinatura
  `v3-http`** (§1/§4) — a injeção do §5 não pode ir ao ar dirigida por um campo
  não assinado; injeção por cabeçalho (§5) com a extensão URL-decodificada do
  `scrubResult`; allowlist de egresso + guarda de SSRF no IP resolvido (§6).
  Fim: um upstream REST aprovado é chamável como tools MCP, com o ponto de
  injeção sob assinatura. Harness: um mock REST em `lab/`, incluindo o teste de
  DNS-rebind do §6 e um teste de credencial refletida em cabeçalho/`Location`.
- **B — OpenAPI → tools + digest de operações na v3.** Ingestão da spec (§3)
  com resolução de `$ref`, união `oneOf`/`anyOf` preservada, namespacing de
  localização, derivação de nome colisão-segura e classe de segurança por
  método; **persistência do conjunto de operações congelado** e seu **digest na
  `v3-http`** (§3/§4); quarentena das tools geradas com classe default-deny
  para métodos não-safe. ADR próprio para o digest de operações na v3.
- **C — rota de proxy reverso restrita.** O mux em `serve.go:582` com a regra
  de prefixo `gatte/` (§7) e o handler que **chama `Dispatch`** (§7). ADR
  próprio para a superfície de ingresso nova.
- **D — endurecimento e docs.** Decisão do egresso http em `entryNetwork`/mapa
  do `0033` (§6), **verificador de egresso que lê `host:porta` da URL assinada
  e afirma igualdade com o mapa de implantação** (não só presença), `README`
  (Security model), `config.example.toml`.

## Consequências

- **O primeiro caminho HTTP de saída do gateway para um backend** nasce aqui
  (hoje só há clientes de saída para o IdP e o socket admin — `oidc.go:222`,
  `check.go:171`, `pkg/adminapi/client.go:73`). Toda a superfície de SSRF e de
  egresso que isso abre é tratada no §6 e é condição de aceite da Fase A.
- **Há campos novos no modelo de dados.** `UpstreamServer` ganha o descritor de
  auth e a classe de segurança por operação (Fase A) e o conjunto de operações
  congelado (Fase B), com migração em `openStore` e codificação canônica
  própria em `signer.go` (§4). Não é só "um dialer chegando".
- **Dois front-ends, um caminho de chamada, uma higienização.** O proxy não
  ganha portões, nem `ReverseProxy`, nem hook de resposta próprio: ele chama
  `Dispatch`, e o `scrubResult` de `Dispatch` (`endpoint.go:2342`) mascara a
  resposta HTTP serializada no `Result` — não há segundo lugar para manter kill
  switch, suspensão, concorrência, quota, record-then-forward ou mascaramento.
- **O ponto de injeção da credencial nunca fica sem assinatura.** O descritor
  de auth e a URL completa (esquema+host+porta+base path) são assinados na mesma
  fase em que passam a dirigir a injeção (Fase A) — uma entrada http não é
  servida com um campo de injeção coberto só pela v1, que não o descreve.
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
  (o `DialContext` sobre a URL assinada) e o mapa de firewall da implantação
  precisam **casar**, senão um `upstream update` que move o host/porta atualiza
  um e deixa o outro velho (dial passa, firewall derruba em silêncio). O
  verificador da Fase D lê `host:porta` da URL **assinada** e afirma que o mapa
  é igual a ele — a URL assinada é a fonte única; alargar o destino continua
  sendo diff assinado, como no `0033`.
- **Não cobre, e não se afirma coberto:** paginação e APIs com estado,
  WebSocket/streaming além do teto de `max_bytes`, o passo `allow_hosts`/
  CONNECT-SNI do `0033` para backends stdio/oci na uid compartilhada (segue
  aberto — §6), saúde REST além de `up` fixo (§2), e injeção de prompt via
  resultado (continua aberta, como no `0014`) — uma resposta de API REST é
  texto de terceiro igual à de um backend MCP.
