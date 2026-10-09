# 0048. REST de OpenAPI nas Fases A+B: operações assinadas, classe de segurança por método com gate na borda de dispatch, e guarda de egresso que desconfia da spec

**Status:** Accepted — 07 out 2026. Refina e executa o `0047` (que fica
`Proposed` como decisão de direção). Este ADR fixa as sub-decisões das suas
**Fases A e B**, entregues juntas: o `0047` §Fases pede um ADR próprio para a
assinatura de operações (Fase B) e para a superfície nova; isto é esse ADR, mais
as correções que uma revisão adversarial contra o código apanhou antes de
qualquer linha de dialer existir.

**Estado de implementação (07 out 2026):** a **fundação** (abaixo, Decisão 2 e o
schema v2) **está no código e testada** — `registry.AuthKind`/`AuthName`/
`Operations`, `registry.Validate` para http (GAB-19 fechado), a tag
`signer.canonical/v3-http`, as três colunas em `registry/sqlite` e
`store.SchemaVersion=2`. A **Decisão 5 landou no mesmo dia, inteira**: as duas
metades (`quarantine.Class`/`SensitiveClearedHash`/`Cleared` com `Usable()`
default-deny; `access.Role.NonRead`/`AllowsExplicitly` e o gate em
`gateway.admit`, que lê a classe da linha de quarentena OU da rota assinada e
roda a cada chamada), o caminho de lote (`ApproveReviewSet` aprova e nunca
libera), `tool clear` na admin API (contrato 1.5.0) e na CLI, e o **schema v3**
(`store.SchemaVersion=3`, colunas `class` e `sensitive_cleared_hash` por ALTER
guardado). **O adapter `resthttp` landou no mesmo dia (07 out 2026), com as
Decisões 6, 7 e 9**: `internal/gateway/resthttp` (modelo de operação com
decode/validação fail-closed e encode canônico; `Dialer` stateless com host-pin
estrutural por `http.Client`, guarda de IP resolvido incluindo `IsUnspecified`,
CGNAT, broadcast e v4-mapped, redação de todo erro de `client.Do` preservando
`errors.Is`, saúde fixa `up` sem `ErrUpstreamGone`), e é o primeiro produtor
real de `ToolDef.SecurityClass = ClassSensitive`. Está **ligado na raiz de
composição**: `cmd/mcp-gateway/dialer.go` roteia `http` para ele com o
`vault.Provider` do `serve`, e `dialTimeRefusal` recusa no `register`/`sign` a
URL e o conjunto de operações que o adapter recusaria, pelas funções do próprio
adapter. A **Decisão 8 ficou dispensada** (ver a nota datada nela): a ordem de
implementação pôs o seam de classe antes do adapter. A revisão do mesmo dia
sobre o adapter apanhou e fechou (sem blocker nem major): `DisableKeepAlives`
para que nenhum buffer de conexão ociosa retenha a última requisição (a
afirmação "o valor nunca é retido" passou a valer do que o upstream aponta, não
só dos seus campos); o envelope mascarado pelo adapter com o valor que **ele**
injetou, fechando a janela de rotação entre o seu `Resolve` e o do
`scrubResult` (`0047` §5, nota); `CredentialDrift` cego a upstreams http (nota
na Decisão 9); `_`/`-` dobrados na comparação de nomes de cabeçalho (slot de
auth, denylist, duplicata); segmento `..;x` e base path com `//` recusados; host
literal proibido recusado no `register`/`sign` e no `Dial`, não só na primeira
chamada; e argumento inválido respondido como `Result{IsError}` em vez de erro
(nota na Decisão 9). **Passo 4 — a ingestão OpenAPI — landou no mesmo dia
(07 out 2026), fechando a ordem de Consequências:** `resthttp.Ingest`
(`internal/gateway/resthttp/openapi.go`, parser próprio, mínimo e fail-closed,
JSON ou YAML, sem dependência nova) produz o `Operations` canônico já validado
por `Validate`/`Encode`/`Decode` — único produtor de `Operation`; nomes só por
`gateway.ValidToolName`, paths só por `ParsePath`, nomes de parâmetro só pela
grammar de token + denylist + slot de auth reservado (Decisão 6); de
`servers[]` só o base path, dobrado no `-url` do operador quando este não tem
um; `oneOf`/`anyOf` sob `body` com `additionalProperties:false` dos ramos
neutralizado (Decisão 4). `cmd/mcp-gateway upstream register -transport http
-openapi FILE|URL -auth-kind -auth-name` monta a entrada (URL com base path
dobrado, descritor dado ou derivado de um único scheme `apiKey`/bearer e
impresso), busca um documento por URL **uma vez** pelo cliente guardado do
adapter (`(*Dialer).FetchDocument`: mesma guarda de egresso, sem credencial,
sem redirect cross-origin, teto de bytes) e imprime as tools geradas com a
classe, as puladas e os avisos. O harness que o `0047` §Fases pedia existe:
`lab/servers/restmock` (API REST falsa que exige a chave em `X-API-Key` e a
**reflete** em `Location`/`Set-Cookie`/corpo) e `make lab-probe-rest`
(`internal/gateway/resthttp/lab_probe_test.go`, `TestLabProbeREST`) provam de
ponta a ponta: chave injetada do cofre no cabeçalho certo (credcheck por
fingerprint), ausente de todo byte devolvido ao cliente e do log do gateway,
mascarada quando refletida, e o `POST` recusado a papel de leitura e ao
`non_read` até o `tool clear` — depois servido só ao `non_read` que o nomeia.
Fica em aberto, declarado: `upstream update` não re-ingere; `upstream list
-json` não mostra descritor/operações de uma entrada http; a referência
completa é a Fase D do `0047`. **Revisão adversarial do Passo 4 (09 out 2026),
corrigida no mesmo passo:** a expansão de `$ref` passou a ser cobrada em
**bytes** enquanto corre (`ingestion.charge`: teto por operação =
`gateway.MaxToolDefinitionBytes`, teto do conjunto = 4 MiB), não só em nós —
um enum de 1 MiB referenciado 300 vezes serializava 315 MB antes do teto ser
checado, e agora é recusado na primeira referência; o YAML é lido por **tag**
(`yaml.Node`), não pelo tipo Go (datas, `1.0` e inteiros grandes como escritos;
`200:` sem aspas lido como `"200"`; aliases expandidos sob teto de nós, porque
decodificar em `yaml.Node` não aplica o limite de aliasing do yaml.v3); o
pré-scan de profundidade, que não protegia nada (o yaml.v3 recusa >10000
níveis), saiu; texto da spec em Skipped/Warnings/erros é escapado
(`internal/visible`) no produtor e no console; o slot de injeção `header` não
pode ser cabeçalho de controle (exceto `Authorization`), dado ou derivado, aqui
e no `registry` (espelho testado); `-auth-kind none` não deriva nem valida sob
o descritor derivado (`IngestOptions.NoDerive`); HEAD/OPTIONS não ganham
`OutputSchema`; `requestBody` em método seguro é pulado, não fatal. **Decisão
que o `0047` §3 pedia explícita, sobre as recusas por-tool do `routesFor`:**
nome, tamanho e a checagem de input schema sobem para o register pelas mesmas
funções (`gateway.ValidToolName`, `DefinitionSize`, `CheckInputSchema`); a
compilação do output schema sobe como **descarte com aviso**
(`gateway.CheckOutputSchema` — o mesmo `resolveOutputSchema` do connect), já
que o output schema é opcional e a tool serve sem ele; o input schema **não** é
compilado (nada no gateway o compila; um `pattern` fora do RE2 fica como
escrito).

## Contexto

O `0047` decidiu a direção: uma API REST registrada (`-transport http`) vira MCP,
uma tool por operação **gerada do OpenAPI**, com a credencial injetada do lado
servidor e a resposta higienizada. Decisões do dono nesta rodada:

- A escolha "API ou MCP" continua pelo **`-transport`**: `http` é uma API REST que
  o gateway transforma em MCP; `stdio`/`oci` são MCP já prontos. Sem flag novo.
- A transformação é por **spec OpenAPI auto-gerada** (`-openapi FILE|URL`), não por
  manifesto escrito à mão. As Fases A (transporte chamável, injeção, egresso,
  assinatura) e B (ingestão OpenAPI → tools, classe de segurança) saem juntas.

Antes de codar, o desenho de cada peça acoplada (adapter `resthttp`, ingestão
OpenAPI, classe de segurança) passou por revisão adversarial contra o código, por
três lentes: existência real das APIs citadas, invariantes do projeto, e
SSRF/segurança. A revisão apanhou um **bypass de autorização em tempo de request**
e um **vazamento de credencial por mensagem de erro** que a versão anterior deste
desenho teria embarcado. As Decisões 5–7 abaixo são a forma corrigida; cada uma
diz o que foi apanhado, para que a correção não se perca como um detalhe de código.

## Decisão

### 1. Uma entrega A+B, duas superfícies sobre um conjunto de operações

Uma API REST registrada tem **um conjunto de operações congelado** (derivado do
OpenAPI no `register`, assinado) e as **tools MCP geradas** sobre ele. Um
registro, uma aprovação de quarentena por tool, uma trilha. A rota de proxy
reverso (`0047` §7) fica para a **Fase C**, não entra aqui.

### 2. A assinatura cobre as operações já na Fase A (não há `v4-http`) — fundação, já landada

O `0047` §4 adiava o digest das operações para um `v4-http` na Fase B. **Isto
muda:** como as operações geradas **existem e roteiam chamadas** desde a primeira
entrega, elas são **persistidas e assinadas junto**. A razão é de segurança, não
de conveniência: o `método+path` de uma operação **não** entra no fingerprint de
quarentena (`quarantine.Hash` cobre `name+description+schema`, não o path) **nem**
na assinatura `v1`. Um write direto no banco que troque `/check` por `/exfil`,
mantendo nome/descrição/schema idênticos, redirecionaria a chamada **sem quebrar
nem a quarentena nem a assinatura**. Logo a `signer.canonical/v3-http` cobre, numa
tag única, `{campos v1 + descritor de auth + SHA-256(Operations)}`. Uma tag
separada (não campos opcionais sob a v1), como a `v2-image`, para que os layouts
nunca coincidam. O **valor** da chave continua fora: rotação não quebra assinatura.

### 3. Descritor de auth: `{kind, name}`, encoding canônico próprio

`kind ∈ {bearer, header, query}` e `name` é o cabeçalho/parâmetro HTTP onde a
chave entra (vazio para `bearer`, que é sempre `Authorization: Bearer`). O valor
vem da **única** entrada de `EnvVarNames` (o secret-ref). Na `v3-http`, `kind` e
`name` são cada um `appendField`-ados (prefixo de comprimento), sem reabrir a
ambiguidade de fronteira que `signer.go` fecha. É o descritor que decide **onde** a
credencial viva é injetada; fora da assinatura, trocar `X-API-Key` por um
parâmetro de query por write direto redirecionaria o segredo e ainda verificaria —
o exato ataque que a assinatura existe para fechar.

### 4. Forma canônica de bytes do `InputSchema` e do conjunto de operações

Fixada agora, porque a quarentena hasheia os bytes crus e `validateSchema` só olha
o `type` de topo (um schema insatisfazível "passa" sem ser correto): `$ref`
resolvido contra os `components` da spec congelada, chaves ordenadas
lexicograficamente, sem espaço insignificante. As operações serializam como um
array JSON ordenado por `Name`; cada `InputSchema` é `json.RawMessage` já canônico.
`allOf` funde no mapa de propriedades; `oneOf`/`anyOf` do `requestBody` preservam a
alternância **sob uma propriedade `body` dedicada** (não como irmão de topo — o AND
de irmãos de topo com `additionalProperties:false` tornaria o schema
insatisfazível), com o `additionalProperties:false` dos ramos liftados
neutralizado. `requestBody` não-objeto vira a propriedade `body` tipada única.

### 5. Classe de segurança por método, com gate class-aware na **borda de dispatch**

Cada operação recebe no `register` uma **classe** derivada do método HTTP:
`ClassSafe` (o zero-value, para `GET`/`HEAD`/`OPTIONS`) ou `ClassSensitive` (os
demais — o `POST /submit` de exfil que o `0047` Contexto nomeia). A classe é
metadado assinado (vai dentro de `Operations`, coberta pelo digest §2). Duas
metades, **construídas juntas** — sem a segunda, "papel distinto" seria só
disciplina de operador, que o `0047` Contexto recusa ("precisa de mecanismo"):

- **Default-deny (servabilidade):** `quarantine.Tool` ganha um campo **ortogonal**
  `Class` (não um 4º `Status`) e um `SensitiveClearedHash`. `Usable()`
  (`quarantine.go:251`) ganha **um conjunto a mais**: uma tool `ClassSensitive` só
  é usável se `SensitiveClearedHash == ApprovedHash`. Como `Usable()` é o portão
  único que `admit` (`endpoint.go:2752`) e a listagem (`health.go:529`) leem, uma
  tool sensível não-liberada fica invisível **e** não-chamável de uma vez, sem
  ramo novo no caminho de chamada.

  *Correção apanhada na revisão:* dois guards pós-aprovação tratam
  "aprovada-mas-não-usável" como **bug interno** (`internal/admin/tools.go:242`,
  `internal/admin/review_set.go:161`). Uma sensível-aprovada-não-liberada
  dispararia esses guards no fluxo normal do operador. Eles são **invertidos** para
  o caso sensível, e o caminho de **lote** (`ApproveReviewSet`) é tratado
  explicitamente — não só o de uma tool.

- **Autorização class-aware na borda de dispatch (fecha o bypass — blocker):** a
  revisão mostrou que `Usable()` é role-blind e `access.Role.Allows`
  (`access.go:200`) é class-blind, e os dois portões do `Dispatch` (`Authorize`
  `:2168` e `admit` `:2173`) **nunca se cruzam**. Um `SensitiveClearedHash` global
  mais um papel de leitura com `grants = {backend = ["*"]}` (GrantAll,
  `access.go:211`) alcançaria a tool sensível liberada, class-blind — e
  `reload.toAccess` reconstrói os papéis e **dropa** marcações de papel, então uma
  checagem só na borda de concessão é point-in-time e não sobrevive a um reload.
  **Decisão do dono:** o `internal/access` **continua casando por nome**
  (`Role.Allows` intacto, não aprende método HTTP); a classe entra como um **passo
  separado na borda de dispatch** que, para uma tool `ClassSensitive`, **recusa a
  cobertura por GrantAll (`*`)** — ela só é alcançável por **id explícito** num
  papel marcado **não-leitura** (`config.Role.NonRead`,
  `adminapi.RoleCoverage.NonRead`). O gate lê a classe (metadado) na borda, não no
  domínio puro; é durável porque roda a cada chamada, não uma vez na liberação.

A classe precisa alcançar essa camada: `gateway.ToolDef` ganha `SecurityClass`
**fora** do fingerprint **por construção** (não entra em `ToolIdentity` nem em
`quarantine.Hash`), `Store.Observe` ganha o parâmetro de classe, e `routesFor`
passa a classe da operação. *Correção factual apanhada na revisão:* a classe fica
fora do fingerprint **porque nunca entra em `ToolIdentity`** — e **não** "espelhando
`OutputSchema`", que, ao contrário do que o desenho afirmava, **está** no
fingerprint quando declarado (ADR-0014/0019).

### 6. Guarda de egresso que desconfia da spec (SSRF)

Com REST o gateway é o cliente HTTP. A guarda, corrigida pela revisão:

- **Host-pin é estrutural, não no `Control`:** `net.Dialer.Control` recebe `IP:porta`
  — o nome DNS já se perdeu ali, então ele **não** pode impor a allowlist de host.
  O pin é um **`http.Client` por upstream que disca só a base assinada**, com
  `CheckRedirect` recusando troca de host. O `Control` faz **só** segurança-de-IP.
- **Recusa pelo IP resolvido** (fecha DNS-rebind/TOCTOU): loopback, IP privado,
  link-local e `169.254.0.0/16`, **mais `IsUnspecified` (`0.0.0.0`/`::`)** — omitir
  isso deixava um rebind para `0.0.0.0` alcançar loopback —, CGNAT `100.64.0.0/10`
  e broadcast.
- **`servers[].url` do OpenAPI é entrada não confiável:** dela se usa **só o base
  path**, dobrado para dentro da URL registrada; o host é sempre o registrado.
  *Correção apanhada:* `Operation.Path` é derivado da **URL assinada**, e um path
  que não comece com um único `/`, ou que contenha esquema, `//authority`, `../` ou
  bytes de controle/CRLF, **falha o registro** — senão uma spec maliciosa injetaria
  SSRF assinado dentro de `Operations` (`http://169.254.169.254/...`, `//evil.tld`).
- **Nomes de parâmetro são entrada não confiável:** todo nome `header_*`/`cookie_*`
  gerado é validado contra a grammar de token HTTP (reusar `registry.authNameChars`)
  **mais** uma denylist de cabeçalhos de controle (`Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Upgrade`, hop-by-hop, segundo `Authorization`)
  — senão o "servidor-vence" protegeria só o slot de auth e deixaria
  request-smuggling/header-injection pelos demais. O slot de auth é reservado
  case-insensitive para header/cookie, servidor-vence.

*Nota de 09 out 2026 (ingestão, Passo 4):* um parâmetro que o documento
declara **no próprio slot da credencial** (`header` com o nome do `AuthName`, em
qualquer caixa e com `_` por `-`, ou `query` com ele) passa a ser **descartado
com aviso**, não recusado. A Petstore pública declara `api_key` em `DELETE
/pet/{petId}`, e a recusa deixava a API inteira de fora por uma declaração que o
"servidor-vence" já torna redundante: o modelo do analista continua sem poder
preencher o slot, e o valor enviado continua sendo o do servidor. `Validate`
segue recusando a propriedade num conjunto que chegue a ela por outro caminho.
Pinado em `TestIngest_AParameterOnTheAuthSlotIsDroppedNotServed`.

### 7. A credencial nunca aparece num erro, nem com `AuthKind=query`

*Correção apanhada na revisão (major):* com `AuthKind=query` o segredo vivo entra na
query string; se `client.Do` falha, `net/http` devolve um `*url.Error` cujo
`.Error()` embute a **URL completa**, com `?<name>=<segredo>`. E o `Dispatch`
devolve o erro de `CallTool` **verbatim** — não há backstop de `redact` como o que
`bringUp`/`resolveEnv` têm em volta de `Dial`/resolve (`endpoint.go:1882,1920`), e
`scrubResult` só roda sobre o `Result`, nunca sobre o `error`. Logo o
`resthttp.CallTool` **redige o valor injetado e a URL de qualquer erro de
`client.Do`** antes de retornar, preservando `errors.Is(context.Canceled/
DeadlineExceeded)`. Em paralelo, `renderingsOf` (`redact.go:92-112`) ganha as formas
**URL-encodadas** (`url.QueryEscape`/`PathEscape`, dedupadas), para o `scrubResult`
mascarar uma credencial refletida percent-encodada num `Location` 3xx/`Set-Cookie`
— o plaintext não tem sequências percent, então sem isso não casaria.

### 8. Fase A interina: só métodos safe até o seam de classe existir

Enquanto a Decisão 5 não estiver fundida, o adapter `resthttp` **restringe o
dispatch a métodos safe (`GET`/`HEAD`)**. Subir o transporte chamável com
`POST`/`PUT`/`DELETE` antes do default-deny de classe reabriria o canal de exfil
que o `0047` nomeia. Depois do seam, os não-safe passam a ser gateados pela classe.

*Nota, 07 out 2026:* **dispensada, não implementada.** A ordem de implementação
(Consequências, item 2 antes do 3) pôs o seam de classe — `Usable()` default-deny
e o gate class-aware em `gateway.admit` — no código **antes** do adapter, então
no dia em que o `resthttp` landou já não havia janela em que um `POST` chegasse a
um upstream sem passar pela classe. O adapter nasceu servindo todos os métodos
válidos, com `ClassOf(método)` como única fonte da classe, e nenhum interino
só-safe foi escrito nem precisará ser removido. A decisão fica registrada como
foi tomada; o que mudou foi a sequência que a tornava necessária.

### 9. Saúde fixa e schema

Um upstream http stateless tem saúde fixa `up` (`0047` §2): `classify` **não** emite
`ErrUpstreamGone` (que faria o gateway re-dialar), uma falha de saída vira
`BackendFailedError`.

*Nota, 07 out 2026 (revisão do adapter):* duas consequências do "stateless" que
o texto acima não nomeava. **(a)** Um argumento que o adapter não consegue pôr
na requisição (chave fora do schema assinado, valor que a localização não
carrega, tentativa ao slot de auth) **não é falha do backend** — o backend nem
foi chamado — e o `Dispatch` transforma todo `error` do `CallTool` em
`BackendFailedError` (ADR-0041 itens 2-3), que mandaria o operador olhar o
backend. O `resthttp.CallTool` responde então com `Result{IsError: true}` e o
motivo (ADR-0041 item 2, "um `isError` que diz o que foi"), sem resolver o
segredo nem tocar a rede; só `ErrUnknownTool` continua `error`, porque uma tool
que o gateway roteia e o conjunto não tem é incoerência gateway↔adapter, não
erro do chamador. **(b)** `CredentialDrift` (`endpoint.go`) pula upstreams cujo
registro é http: a premissa do drift — valor copiado uma vez no dial para um
processo que o guarda — é falsa para um adapter que re-resolve por chamada
(`0047` §5), e o aviso "STILL USING THE OLD VALUE … run `upstream redial`" seria
falso com remédio inútil. Os digests continuam registrados no `bringUp`, porque
o `scrubResult` lê deles os **nomes** a mascarar.

`store.SchemaVersion` vai a **3** na mudança que adiciona as
colunas de classe em `quarantine/sqlite` (ALTER guardado, como a fundação fez para
`registry/sqlite` no v2); o `quarantine/sqlite` hoje só tem `CREATE TABLE IF NOT
EXISTS`, então o ALTER guardado é introduzido com esta mudança.

## Consequências

- **O caminho de chamada não ganha ramo novo, mas o modelo de autorização ganha um
  gate.** O proxy e as tools passam por `Dispatch`; a novidade é o passo de classe
  na borda de dispatch (Decisão 5), que lê metadado e não ensina método HTTP ao
  `access`. É uma gate a mais, documentada, não uma regra escondida.
- **A classe é assinada e durável.** Vive no `Operations` assinado e no banco de
  quarentena; sobrevive a restart e a reload, e o gate roda a cada chamada.
- **A spec do OpenAPI é tratada como texto de terceiro em toda aresta** — host,
  path, nomes de parâmetro. O destino, o path e os nomes vêm validados ou da URL
  **assinada**, nunca da spec crua.
- **Ordem de implementação** (dependências corrigidas pela revisão): (1) prereqs —
  exportar o predicado de nome de uma fonte só (`gateway.ValidToolName`) e a
  extensão URL-encodada do `renderingsOf`; (2) o seam de classe (as duas metades +
  o gate de dispatch + o caminho de lote + schema v3) **antes** do adapter; (3) o
  adapter `resthttp` (com a redação de erro, `IsUnspecified`, host-pin estrutural,
  e o interino só-safe); (4) a ingestão OpenAPI (validação de nome/path, produtor
  único de `ToolDef`, digest na `v3-http`).

## Não cobre, e não se afirma coberto

Proxy reverso `gatte/<nome>/...` (Fase C); `entryNetwork` http e o verificador de
egresso contra o mapa de firewall (Fase D, `0047` §6); OAuth (cunhar token
próprio, `AGENTS.md` §2); paginação e APIs com estado; WebSocket/streaming além do
teto de `max_bytes`; e injeção de prompt via resultado (segue aberta, como no
`0014`) — uma resposta REST é texto de terceiro igual à de um backend MCP.
