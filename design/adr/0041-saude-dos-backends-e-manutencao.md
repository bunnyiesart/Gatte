# 0041. Saúde dos backends e manutenção: dizer ao modelo que o servidor caiu

**Status:** Proposed — 29 set 2026. Desenho; passa a Accepted no commit que
entrega a implementação, e as notas de correção nas ADRs 0012, 0020, 0021,
0024 e 0040 entram nesse mesmo commit, porque até lá as frases delas ainda
são verdadeiras.

## Contexto

O dono relatou: **o Claude Code sempre acha que o problema é qualquer coisa,
menos o servidor MCP ter caído.** A medição que sustenta este ADR foi feita
com um servidor MCP descartável no go-sdk v1.8.0 (o do `go.mod`) em modo
stateless, como o `httpapi`, uma API Anthropic falsa que registra o que o
modelo recebe, e o Claude Code 2.1.285 com `HOME` e configuração temporários.
O que ela mostrou, e o que o código de hoje faz em cada caso:

1. **Um erro JSON-RPC chega ao modelo como `error.message` e nada mais.** O
   `error.data` é descartado nos dois runtimes do cliente. Um backend morto
   hoje vira `"internal error"` (`httpapi/errors.go`, `classify` →
   `classInternal`), e é isso, literalmente, que o modelo lê. Nada ali diz
   que é uma queda.
2. **Um resultado com `isError: true` chega com o texto inteiro.** A spec
   (2025-11-25, *Error Handling*) põe falha de API em *tool execution error*
   e diz que o cliente SHOULD entregá-lo ao modelo; o erro de protocolo é
   MAY. É o canal certo para uma explicação com vários campos.
3. **A lista de tools é lida uma vez, no connect, e nunca mais** — nem depois
   de erro, nem depois de `unknown tool`, nem depois de 503. Um servidor
   stateless não consegue empurrar `list_changed` (o `getServer` cria um
   `mcp.Server` por requisição). Então **podar as rotas de um backend morto
   não compra nada no meio da sessão**: o modelo continua com as tools e
   passa a receber `unknown tool "casemgmt.list_cases"` — que é o que a
   ADR-0024 produz hoje assim que a re-discagem falha e o `Refresh` monta a
   tabela só com os conectados. E para a sessão que começa durante a queda,
   as tools simplesmente não existem. Nos dois casos o modelo conclui
   "nome errado" ou "não tenho essa capacidade".
4. **As `instructions` do `initialize` chegam ao modelo** (runtime v1 pelo
   `initialize`, v2 pelo `server/discover`, os dois preenchidos por
   `ServerOptions.Instructions`), num bloco "MCP Server Instructions", com
   corte em 2.048 caracteres. Com tool search ligado, que é o padrão, são o
   único texto do servidor que o modelo sempre vê. O Gatte não manda
   nenhuma hoje.
5. **Quando o próprio processo não responde, nada dentro da banda ajuda:**
   `ECONNREFUSED`/`ECONNRESET` chegam como texto cru. Um 503 com corpo curto
   chega ao modelo e ao usuário (`claude mcp list`), então um proxy à frente
   pode dizer "em manutenção". Mas isso só existe se algo à frente responde.

O que o gateway já tem e este ADR reaproveita: a detecção de morte da
ADR-0024 (`ErrUpstreamGone`, `markGone`, re-discagem na rodada seguinte), as
definições aprovadas guardadas pela ADR-0032 (`quarantine.Store.Definition`),
o batimento da ADR-0021, as linhas de evento `(gateway)` da ADR-0032, a API de
gestão com identidade do kernel da ADR-0040 e o script de conexão da
ADR-0039.

O que não pode mudar: o chamador não aprende **por que** uma parte está mal
(`classify` existe para isso), o texto de erro de um upstream nunca é
repassado (ele pode ecoar a credencial; ver `gateway.auditFailure`), quem
não tem uma tool concedida continua recebendo a recusa constante, e a
quarentena não ganha nenhum caminho para servir uma definição que um humano
não aprovou.

## Alternativas

### Opção A — Só texto melhor no erro JSON-RPC

| Prós | Contras |
|---|---|
| Uma linha em `errors.go` | O cliente entrega `message` e descarta `data`; o texto teria de caber numa mensagem que hoje é constante por classe, e erro de protocolo é MAY na spec |
| — | Não resolve o `unknown tool` das tools podadas, que é metade do problema |

### Opção B — Empurrar `list_changed` por uma stream de `subscriptions/listen`

| Prós | Contras |
|---|---|
| O go-sdk v1.8.0 implementa (SEP-2575) e o runtime v2 abre a stream | Exige uma stream longa por analista num gateway que é stateless por decisão, e um `mcp.Server` vivo por sessão em vez de um por requisição |
| — | Tirar a tool da lista é justamente o que produz `unknown tool`; o que falta é o contrário |

### Opção C — Resultado honesto, lista estável, `gatte.status`, manutenção persistida (escolhida)

| Prós | Contras |
|---|---|
| Usa o único canal que a spec e a medição garantem até o modelo (`isError`) | Um texto novo chega ao modelo, e cada campo dele precisa de argumento de por que pode sair (item 3) |
| A lista não muda durante a queda, então a sessão que começou antes e a que começa durante veem o mesmo mundo | Uma tool de backend caído continua anunciada; o modelo pode tentá-la e receber "indisponível" |
| Zero processo novo, zero dependência nova: uma tabela, um port, uma tool embutida e um script de shell | O `serve` passa a escrever no banco a cada rodada (uma transação pequena a cada `refresh_interval`) |

## Decisão

**Opção C**, em oito peças.

### 1. A máquina de estados de um backend

"Backend" aqui é uma entrada do registro que passou, na rodada mais recente,
por todos os portões do `Reconcile`: `Validate`, cobertura de quota (não é
`uncounted`) e assinatura verificada — o conjunto `want` de hoje, que passa
a ser guardado no `Gateway` como `servable`. Uma entrada fora dele não tem
estado: não é servida, como hoje.

Por baixo há **um fato de vida**, mantido pelo gateway em memória:

| campo | o que é |
|---|---|
| `live` | há uma conexão aberta para ele e ela não foi marcada morta (`gone`) |
| `since` | quando `live` assumiu o valor atual, neste processo |
| `last_attempt` | a última discagem tentada, com ou sem sucesso; vazio se nenhuma ainda |
| `cause` | só para o operador: `process_gone` (ADR-0024 viu o processo acabar), `not_brought_up` (a discagem falhou), `held_back` (discagens congeladas pela divergência quota × registro) |

Por cima há **o estado público**, derivado na hora, na ordem:

1. `maintenance` — existe uma linha de manutenção para ele (item 6). Vence
   tudo: é o que o operador disse, e as chamadas não são discadas.
2. `up` — `live`.
3. `reconnecting` — não `live`, e a próxima rodada vai discá-lo.
   `next_attempt` é o início da última rodada mais `refresh_interval`
   (durante a suspensão, 5 s), dito como "por volta de": o laço reinicia o
   timer depois do trabalho (ADR-0020 item 5).
4. `down` — não `live`, e nenhuma discagem está marcada: o `Reconcile` está
   congelado (`held_back`). Sem `next_attempt`; o texto diz que um operador
   precisa agir, sem dizer por quê.

Transições de `live`, e só elas, mexem em `since`:

- `Connect` e cada `Reconcile`: depois de `retire` e `adopt`, todo nome de
  `servable` é conferido; o que discou e entrou vira `live`, o que discou e
  falhou fica não-`live` com `last_attempt` = agora.
- `markGone` (chamado pelo `Refresh` e pelo `Dispatch`, como hoje) põe
  `live` em falso **na hora**, com `cause = process_gone`. Não fecha nada: o
  fechamento continua sendo do `Reconcile` (ADR-0024 item 3). O que muda é que
  a conexão marcada não recebe mais chamadas (item 2).
- Um nome que sai de `servable` sai da máquina (e escreve a linha de saída,
  item 7).

Um backend cuja listagem falha sem `ErrUpstreamGone` continua `up`: *não
listar* não é *ter morrido* (ADR-0024 item 1). Timeout, cancelamento, erro
genérico e resultado recusado (tamanho, schema, credencial) ficam como estão
hoje — erro interno constante — porque não são estado de disponibilidade e,
num resultado grande demais, a culpa pode sim ser do pedido.

### 2. O que o chamador vê: resultado com `isError: true` e texto fixo

A ordem do `Dispatch` ganha um passo, e o lugar dele é a propriedade de
segurança:

```
0 bloqueio (0031)   → forbidden
  suspensão (0020)  → (item 8)
1 rota              → unknown tool
2 Authorize         → forbidden
3 quarentena        → unknown tool
4 DISPONIBILIDADE   → resultado honesto              ← novo
5 vaga (0035), 6 quota (0030), 7 linha allowed, 8 chamada ...
```

**Depois de 2 e 3**, para que só quem já pode chamar aquela tool aprovada
aprenda o estado do backend dela: a quem não foi concedida continua
recebendo o `forbidden`, e uma tool em quarentena continua sendo
`unknown tool`, byte a byte como hoje — o estado não vira oráculo de postura.
Quem não tem a tool no papel nem a tem registrada no seu `mcp.Server`, então
o SDK responde `unknown tool` antes de qualquer código do gateway, como hoje.
**Antes de 5 e 6**, para que uma chamada que não sai do processo não gaste
vaga nem debite quota.

O passo 4 responde, sem discar, quando:

- o backend está em `maintenance` → texto de manutenção;
- a rota não tem conexão (lista estável, item 4) ou a conexão está marcada
  `gone` → texto de `reconnecting` ou `down`.

E o passo 8 ganha um caso: a chamada **em voo** que volta com
`ErrUpstreamGone` continua escrevendo `allowed` + `failed` (`upstream gone`)
como hoje, mas o chamador recebe o texto de `reconnecting` (com `since` =
agora e sem tentativa ainda) em vez de `internal error`.

O resultado é um `CallToolResult` com `isError: true`, um único bloco
`text`, sem `structuredContent`. O texto é montado em
`internal/gateway/httpapi/errors.go` — o arquivo onde se revisa "o que pode
vazar" continua sendo um só — a partir de um erro tipado
(`*gateway.UnavailableError`) cujos campos o gateway preenche **só com estado
dele**: nome do backend, estado, instantes, mensagem do operador. Nenhum
campo vem de erro, stdout, stderr ou resultado de upstream. Os modelos, em
inglês como o resto do fio (`unknown tool`, `forbidden`), com instantes em
RFC 3339 UTC com segundos:

**reconnecting**

```
Gatte: the backend "casemgmt" is unavailable since 2026-09-29T14:02:11Z; Gatte is reconnecting it (last attempt 2026-09-29T14:05:00Z, next attempt around 2026-09-29T14:10:00Z). This is not a problem with your request or its arguments: do not change them. Retry after the next attempt, or tell the user. Call gatte.status for the current state of your backends.
```

Sem tentativa ainda: `(no reconnect attempt yet, next attempt around ...)`.

**down**

```
Gatte: the backend "casemgmt" is unavailable since 2026-09-29T14:02:11Z (last reconnect attempt 2026-09-29T14:05:00Z). Gatte is not reconnecting it automatically; an operator has to act. This is not a problem with your request or its arguments: do not change them. Tell the user. Call gatte.status for the current state of your backends.
```

**maintenance**

```
Gatte: the backend "casemgmt" is in planned maintenance since 2026-09-29T13:00:00Z, expected until 2026-09-29T15:00:00Z. Operator message: "Troca de versão do casemgmt". This is not a problem with your request or its arguments: do not change them. Retry after the maintenance, or tell the user. Call gatte.status for the current state of your backends.
```

Sem `until`: `with no announced end`. Com `until` já passado: `expected
until ... (that time has passed; the maintenance has not been ended yet)`.
O `until` é previsão, não prazo: a manutenção só acaba por um `off`
explícito (item 6).

A trilha: a recusa do passo 4 é uma linha `denied` do analista, com razão
`backend unavailable: reconnecting`, `backend unavailable: down` ou
`backend in maintenance`, target o backend. São recusas, como
`registry unavailable` já é: nada saiu do processo. As três entram em
`TestAuditReasons_AreAStableWireContract`.

### 3. Por que é seguro dizer isso, e a quem

O que sai, e só para um chamador autenticado, não bloqueado, com a tool
concedida e aprovada:

| sai | por que pode |
|---|---|
| o nome do backend | já está no nome da tool que ele mesmo chamou (`casemgmt.`) |
| o estado e os instantes | fato operacional de um sistema que o papel dele já o autoriza a usar; é o que ele precisa para decidir esperar ou avisar |
| a próxima tentativa | é o intervalo de configuração, não um segredo |
| a mensagem de manutenção | escrita pelo operador **para** os analistas, validada (item 6) |

O que **não** sai, nunca: a causa (`cause`), o texto de erro do upstream, o
código de saída, host, imagem, comando, credencial, quem abriu a
manutenção, o estado de qualquer backend em que ele não tem tool, contagem
de tools ou de analistas. A frase "Gatte is not reconnecting it
automatically" do `down` diz que existe um problema de operação, não qual —
a divergência quota × registro fica no log e na trilha.

A regra de `classify` fica: **nenhum texto derivado de erro chega ao
cliente.** O que muda é que passa a existir uma classe cujo texto é montado
de estado do gateway, não de erro, e ela é a única.

### 4. A lista estável

**Regra:** uma tool de um backend em `servable` que não está `live` continua
na tabela de rotas com a **definição aprovada guardada**, enquanto:

1. a entrada continua em `servable` (registrada, válida, assinada, coberta
   pela quota) — o `Reconcile` reavalia a cada rodada;
2. a tool é `Usable` na quarentena — relido a cada `tools/list` e a cada
   chamada, como hoje (`admit`);
3. `Store.Definition(ApprovedHash)` devolve a definição e ela ainda passa
   por `validToolName`, `validateSchema` e pelo teto de tamanho, as mesmas
   regras do `routesFor`.

A fonte é o **store**, não a memória, nas duas situações — a queda no meio
da vida do processo e o arranque com o backend fora — para que haja um
caminho só. `Usable` exige `ObservedHash == ApprovedHash`, então a definição
guardada é exatamente a que um humano aprovou e a última que o backend
anunciou. Nada é `Observe`ado: uma definição lida do store não é uma
observação e não mexe na quarentena.

**Nada ressuscita.** Uma tool `pending` ou `changed` não é `Usable` e não
entra. Uma aprovação anterior à ADR-0032 (`ErrDefinitionNotKept`) não entra
— limite declarado, logado uma vez por rodada. Quando o backend volta, o
`Refresh` observa de novo o que ele anuncia, e uma reescrita vira `changed`
e sai, como hoje. Quarentena ilegível durante o `Refresh` mantém as rotas
anteriores daquele nome, pela regra que já existe (`unmeasured`).
`mergeRoutes` (colisão) e `withholdUndeclaredQuotaTools` rodam sobre a
tabela inteira, as rotas estáveis incluídas.

**Quanto tempo:** sem limite de tempo, enquanto as três condições valerem.
O argumento: tirar da lista não esconde a tool do modelo no meio da sessão
(Contexto, 3) e só troca uma resposta honesta por `unknown tool`, que é o
defeito. Lista não é fronteira de segurança — a fronteira é o
`Authorize` + `admit` por chamada, que não muda. As alavancas do operador
para tirar um backend da frente dos analistas são as que já existem ou que
este ADR cria: `upstream deregister` (sai da lista na rodada seguinte, como
hoje), assinatura retirada (idem) e manutenção (fica na lista, com texto).

**Quando a entrada sai do registro ou perde a assinatura:** sai de
`servable`, o `retire` apaga as rotas como hoje, e a tool some. É o
comportamento de hoje, mantido de propósito: essa é uma decisão do
operador, não uma queda.

### 5. `gatte.status`: a tool embutida

**Nome reservado.** O namespace `gatte` é do gateway:
`registry.UpstreamServer.Validate` recusa o nome `gatte` sem diferenciar
maiúsculas, e o `Connect`/`Reconcile` já reaplicam `Validate` a toda entrada
lida do banco, então uma entrada escrita direto no SQLite com esse nome
também é recusada. Nenhuma rota da tabela pode, portanto, começar com
`gatte.`; um teste afirma isso sobre a tabela, não sobre a intenção. O nome
segue a forma `backend.tool` de todas as outras tools, que o Claude Code já
atende em produção como `mcp__<servidor>__casemgmt.list_cases`.

**Fora da quarentena por construção.** A definição é compilada no binário;
não há upstream que a anuncie, portanto nada a observar, aprovar ou
reescrever. Ela não passa pelo `routesFor` nem pelo `Store`, e não aparece
em `tool list`.

**Sempre disponível** para todo chamador autenticado e não bloqueado, sem
depender do papel: é registrada pelo `getServer` em todo `mcp.Server`, fora
do laço das tools concedidas. Não passa por vaga nem quota (não sai do
processo, não gasta conta de terceiro). Grava uma linha `allowed`, tool
`gatte.status`, target `(gateway)`, porque toda `tools/call` produz
exatamente uma linha (GAB-16).

**Definição** (a descrição é curta de propósito: o cliente corta em 2.048):

```json
{
  "name": "gatte.status",
  "description": "Reports whether Gatte and each backend you can use are up, reconnecting, down or in planned maintenance, and when to retry. Call it when a tool call fails as unavailable or in maintenance, before assuming any other cause. Takes no arguments.",
  "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
  "annotations": {"readOnlyHint": true, "idempotentHint": true, "openWorldHint": false},
  "outputSchema": {
    "type": "object",
    "required": ["checked_at", "gateway", "backends"],
    "properties": {
      "checked_at": {"type": "string", "format": "date-time"},
      "gateway": {
        "type": "object", "required": ["state"],
        "properties": {
          "state": {"enum": ["normal", "maintenance"]},
          "since": {"type": "string", "format": "date-time"},
          "until": {"type": "string", "format": "date-time"},
          "message": {"type": "string"}
        }
      },
      "backends": {
        "type": "array",
        "items": {
          "type": "object", "required": ["name", "state"],
          "properties": {
            "name": {"type": "string"},
            "state": {"enum": ["up", "reconnecting", "down", "maintenance"]},
            "since": {"type": "string", "format": "date-time"},
            "last_attempt": {"type": "string", "format": "date-time"},
            "next_attempt": {"type": "string", "format": "date-time"},
            "until": {"type": "string", "format": "date-time"},
            "message": {"type": "string"}
          }
        }
      }
    }
  }
}
```

**O que revela:** os backends que têm **pelo menos uma tool na lista servida
a este chamador nesta requisição** (os prefixos de `caller.tools`), e nenhum
outro. Não "concedido pelo papel": um backend cujas tools concedidas estão
todas em quarentena não aparece, porque aparecer diria que existem tools
concedidas ali que a quarentena segura — o oráculo que a ADR-0007 fecha.
Assim o `gatte.status` nunca revela um backend que o `tools/list` do mesmo
chamador já não revela. Um chamador sem tools recebe o bloco `gateway` e
`backends: []`. Os campos por backend são os do item 3, e nada além.

O resultado leva `structuredContent` com o objeto acima e um bloco `text`
com a mesma informação, uma linha por backend, para cliente que só lê texto:

```
Gatte status at 2026-09-29T14:06:00Z.
Gateway: normal.
casemgmt: up since 2026-09-29T08:00:03Z.
logsearch: reconnecting since 2026-09-29T14:02:11Z; last attempt 2026-09-29T14:05:00Z; next attempt around 2026-09-29T14:10:00Z.
docsearch: in planned maintenance since 2026-09-29T13:00:00Z, expected until 2026-09-29T15:00:00Z. Operator message: "Reindexação".
```

**Instructions** (`ServerOptions.Instructions` no `getServer`, uma por
requisição, sem nada do chamador; a diretiva vem na primeira frase porque o
cliente corta em 2.048 e a doc do cliente pede o crítico no começo):

```
If a Gatte tool call fails saying its backend is unavailable, reconnecting, down or in planned maintenance, call gatte.status before assuming any other cause: the problem is that backend, not your request, so do not rewrite a correct request. Tool names are backend.tool. If the Gatte server itself cannot be reached, tell the user to run gatte-status in a terminal on their machine.
```

Com o gateway em manutenção (item 6), acrescenta-se uma frase com a mensagem
e o `until`. O texto inteiro fica abaixo de 1.024 caracteres; um teste mede.
As instructions só chegam a sessões que conectaram — cobrem a queda de um
backend no meio da sessão, não o Gatte fora no início (item 8).

### 6. Manutenção planejada

**O que é.** Uma linha por alvo: um backend pelo nome, ou o gateway inteiro.

| campo | regra |
|---|---|
| `message` | obrigatória; 1 a 200 caracteres depois de `TrimSpace`; uma linha; recusa (não escapa) controle C0/C1 e todo code point que `internal/visible` chama de escondido (bidi, largura zero) — ela vai ao modelo como texto do gateway |
| `until` | opcional; RFC 3339; no futuro no momento em que é gravada e a no máximo 90 dias (pega o ano digitado errado); guardada em UTC; **previsão, não prazo** |
| `set_by`, `set_at` | o operador (identidade do kernel, ADR-0040 §2) e o instante; **nunca** vão a analista |

`until` não expira sozinho de propósito: uma troca de versão que atrasa e
"acaba sozinha" às 15h mandaria chamadas para um backend pela metade. O que
o analista vê depois do `until` é "o horário passou e a manutenção não foi
encerrada", que é verdade e leva o usuário a perguntar.

**Backend em manutenção:** as chamadas recebem o texto de manutenção sem
discar (item 2). O ciclo de vida não muda: o `Reconcile` continua fechando e
re-discando como sempre, e o `Refresh` continua observando. Parar as
re-discagens seria um segundo controle de ciclo de vida, e o que já existe
para isso é `upstream deregister`. As transições de `live` durante a
manutenção continuam indo à trilha (item 7): o operador que reinicia o
contêiner vê o `down` e o `up` que ele mesmo causou.

**Gateway em manutenção:** é um **aviso**, não um bloqueio — o `serve`
continua servindo tudo. Ele aparece:

- como um bloco `text` **acrescentado ao fim** de todo resultado de
  `tools/call` — de upstream, honesto ou do `gatte.status` — depois da
  verificação de tamanho e schema e do scrub, então não conta contra o teto
  e não toca `structuredContent`:
  `Gatte notice: the Gatte gateway is in planned maintenance since T, expected until U. Operator message: "...". Calls are still being served; if one fails as unavailable, call gatte.status.`
- no bloco `gateway` do `gatte.status`;
- nas instructions das sessões que conectam durante ela.

Uso previsto: o operador anuncia com antecedência a parada do `serve`
(atualização do binário, reinício do host), com `until`; os modelos das
sessões abertas leem o aviso em cada resultado; na parada em si, nada no
processo responde (item 8).

**Onde vive.** Tabela `maintenance` no banco do gateway, num adaptador novo
`internal/health/sqlite` com `Migrate` idempotente, ligado no `openStore`
(o `internal/fitness/migrate_test.go` falha até ligar). Chave `target`:
o nome do backend, ou `(gateway)` — entre parênteses, como os atores, para
não colidir com nome de registro, cujo charset não tem parênteses.

**Leitura pelo `serve`:** uma leitura por chamada da tabela inteira (poucas
linhas, um `SELECT`), como o bloqueio da ADR-0031 é lido por chamada, e por
isso **efetiva sem restart** na chamada seguinte. **Falha de leitura é
tratada como "sem manutenção"** e logada: manutenção é aviso de
disponibilidade, não controle de acesso, e recusar por ela transformaria um
soluço do banco numa queda anunciada como manutenção. (O bloqueio, que é
controle, continua fail-closed; a diferença é deliberada.) O batimento
reporta a leitura falha como `-1`/`unknown` (item 7).

**Quem abre e fecha.** Só o operador, pelo socket do operador (ADR-0040),
com identidade do kernel, pelo `internal/admin.Service` — que o CLI e a API
usam igualmente:

- API: `GET /v1/maintenance`, `POST /v1/maintenance/on`,
  `POST /v1/maintenance/off` (contrato 1.1.0, feature `maintenance`);
- CLI:
  ```
  mcp-gateway upstream maintenance on NAME -message TEXT [-until RFC3339|DURAÇÃO]
  mcp-gateway upstream maintenance off NAME
  mcp-gateway maintenance on -message TEXT [-until RFC3339|DURAÇÃO]     # o gateway inteiro
  mcp-gateway maintenance off
  mcp-gateway maintenance list [-json]
  ```
  `-until 2h` é relativo ao agora e só existe no CLI; a API recebe instante
  absoluto.
- front do Gatte: página Backends (estado, desde, próxima tentativa, causa;
  formulário de manutenção por backend, POST com CSRF) e Overview (aviso do
  gateway, backends fora de `up`, `serve` sem reportar); os fronts de
  terceiros, pelo mesmo `pkg/adminapi`.

**Ordem gravar/registrar:** as duas operações mudam primeiro e registram
depois, com `recorded: false` e `audit_write_failed` se a trilha falhar
(ADR-0040 §3). Não se copia a ordem invertida do `unblock` (ADR-0031):
aquela existe porque desbloquear alarga acesso; encerrar manutenção não
alarga nada que o papel já não conceda. Repetir `on` com a mesma mensagem e
o mesmo `until` responde `changed: false`; com outros, atualiza e grava
linha. `off` sem manutenção responde `changed: false`. Backend que não está
no registro: `not_found`. As duas são `x-gatte-idempotent: true`.

`upstream deregister` apaga também a manutenção e a saúde do nome, pela
mesma razão do `Forget` da quarentena: um nome registrado de novo não herda
estado de outro.

### 7. Sinais: trilha, batimento, e o que o front lê

**Linhas de transição**, escritas pelo gateway, identidade `(gateway)`, tool
`(backend health)`, target o nome do backend, pelo mesmo `record` de toda
linha — portanto também no JSONL e no GELF. **Só em transição de `live`:**

| quando | outcome | reason |
|---|---|---|
| primeira observação do backend neste processo, vivo | `allowed` | `backend up: first observed` |
| primeira observação, não vivo | `denied` | `backend down: <cause>` |
| vivo → não vivo | `denied` | `backend down: process_gone` / `not_brought_up` / `held_back` |
| não vivo → vivo | `allowed` | `backend up: down since <RFC 3339>` |
| sai de `servable` sem ser por manutenção | `denied` | `backend removed: no longer servable per the registry` |

A primeira observação por processo existe para que o SIEM tenha uma máquina
de estados exata: sem ela, um `down` antes de um restart e um backend que
voltou bem depois dele deixariam um incidente aberto para sempre. Custa uma
linha por backend por boot. A causa na trilha é aceitável: a trilha é do
operador; é o chamador que não a vê. `down` é `denied` pela regra da
ADR-0032 (o gateway deixando de servir algo); `up` é `allowed` (o gateway
voltando a servir), e quem conta chamadas já exclui as linhas `(gateway)`.

**Manutenção** não tem linha do gateway: a linha é a do operador, escrita
pela API/CLI, identidade `(operator:NOME)`, tool `(maintenance on)` ou
`(maintenance off)`, target `(gateway)` como toda linha de operador,
reason `upstream "casemgmt": [ui] until 2026-09-29T15:00:00Z: "Troca de versão"`
ou `gateway: [cli] until ...: "..."`. Sem `until`: `no announced end`.

**Batimento (`jsonl.Version` 5).** Cinco campos novos, conjunto fechado, sem
nome de backend (a regra do `Status` da ADR-0021):

| campo | o que é |
|---|---|
| `backends_up`, `backends_reconnecting`, `backends_down` | contagem pelo estado **de vida** (manutenção não entra aqui) |
| `backends_maintenance` | backends com linha de manutenção; `-1` se a tabela não pôde ser lida neste batimento |
| `gateway_maintenance` | `on`, `off` ou `unknown` |

`upstreams` continua sendo "conectados" e continua sem cair durante o reparo
de uma rodada (ADR-0024); a queda aparece nas contagens novas e na trilha.

**Estado para os fronts.** O backend de gestão é outro processo (ADR-0040
§4) e não enxerga a memória do `serve`. Então o `serve` grava, na mesma
migração, duas tabelas pequenas: `backend_health` (uma linha por backend:
`live`, `since`, `last_attempt`, `cause`, `updated_at`) e `serve_status`
(uma linha: `boot`, `last_round_at`, `round_interval`). Grava em cada
transição e no fim de cada rodada, numa transação; falha de escrita é
logada e não afeta nada servido. O `GET /v1/overview` e o `GET /v1/upstreams`
leem essas tabelas; o `serve_status` dá ao front **o `serve` parado**:
`last_round_at` mais velho que duas vezes o intervalo mais o
`reconcileTimeout` vira `not_reporting`, que é o que o operador precisa ver
quando o console abre e o gateway não está lá.

### 8. O Gatte inteiro fora

**Suspensão (ADR-0020).** Hoje uma requisição autenticada com a frota
suspensa recebe `500 internal error`, e o cliente diz ao modelo que o
servidor "falhou ao conectar" com esse texto. Passa a receber
`503` com corpo constante, sem dizer qual parte:
`Gatte is temporarily unable to serve tools. This is not a problem with your request; retry in a few minutes or tell the user.`
É o mesmo nível de revelação do `500` (constante por classe, só depois da
autenticação) com a informação que o cliente e o modelo precisam: é
passageiro. A distinção da ADR-0020 item 4 (suspensão ≠ lista vazia ≠ tool
desconhecida) fica, agora legível também do lado do cliente.

**Processo parado ou inalcançável.** Nada dentro da banda ajuda. Duas peças:

**(a) `gatte-status` na máquina do analista.** O script de conexão
(ADR-0039) passa a instalar um comando pequeno, renderizado com os mesmos
valores validados (URL, nome do servidor, CA) e nenhum outro:

- sh: `~/.config/gatte/bin/gatte-status`, `0755`, e o diretório no `PATH`
  pela mesma linha única no perfil do shell que já existe para o CA;
- PowerShell: `%USERPROFILE%\.gatte\gatte-status.ps1` e um
  `gatte-status.cmd` que o chama com `-ExecutionPolicy Bypass`, com
  `%USERPROFILE%\.gatte` no `PATH` do usuário, uma vez.

O que ele faz, em ordem, parando no primeiro que falha:

| passo | como | diz |
|---|---|---|
| 1. o gateway responde? | `GET` na metadata de recurso protegido (RFC 9728), com o CA quando há | código de saída do curl 6 → nome não resolve (VPN/DNS); 7 ou 28 → sem conexão (VPN, host fora); 35/51/58/60/77 → TLS (rode o `connect-gatte` de novo); HTTP 502/503/504 → o proxy responde e o Gatte não (fora do ar ou em manutenção), com as primeiras 300 posições do corpo, sem caracteres de controle |
| 2. o endpoint MCP é o Gatte? | `POST` sem token na URL MCP; espera `401` com `WWW-Authenticate` contendo `resource_metadata` | outra resposta → algo à frente não é o Gatte |
| 3. o Claude Code está logado? | `claude mcp get NOME` | `Needs authentication`/falha → "abra o `claude`, digite `/mcp`, escolha NOME e autentique" |
| 4. os backends | só com `-backends`: `claude -p` restrito a `mcp__NOME__gatte.status`, que imprime o texto do `gatte.status` | opcional porque gasta uma requisição do modelo |

Saída: 0 tudo certo; 1 rede; 2 TLS; 3 o proxy responde e o Gatte não;
4 Gatte de pé mas o Claude Code não está autenticado ou configurado;
5 inesperado. Não lê token, não imprime cabeçalho além de dizer se o
desafio veio, não guarda nada.

**Por que não há endpoint público novo.** A metadata é respondida pelo
primeiro ramo do `ServeHTTP` do próprio `serve`, então um 200 ali já prova
DNS, rede, TLS, proxy e o handler do processo de pé; o `401` do passo 2
prova o caminho de autenticação. Um `/healthz` não acrescentaria nada que
esses dois não mostram. O estado por backend é por chamador (item 5) e
exige identidade, portanto é dentro da banda; um endpoint sem autenticação
com estado de backends revelaria a frota a quem alcança o host. Durante uma
suspensão a metadata continua 200; o passo 4 (ou o próprio Claude Code) vê
o `503` constante.

Para a parada planejada do `serve`, o operador **pode** fazer o proxy à
frente responder `503` com uma frase curta de manutenção enquanto o upstream
está fora; o corpo chega ao modelo e ao `gatte-status` (passo 1). É
configuração do proxy, fora do Gatte, documentada como receita.

**(b) O lado do operador.**

- O `serve` roda sob systemd com `Restart=on-failure` (unit da implantação);
  `systemctl status` e o journal dizem o motivo.
- Alertas no SIEM: (i) silêncio de `type:heartbeat` por três intervalos
  (ADR-0021, já existe); (ii) `tool:"(backend health)" AND outcome:denied`
  abre, e o `allowed` do mesmo target fecha; (iii) `boot` novo no batimento
  é um restart; (iv) `backends_down > 0` por mais de dois batimentos.
- O console mostra `serve` `not_reporting` (item 7) mesmo com o `serve`
  parado, porque o backend de gestão lê o banco e não o processo.
- Roteiro de parada planejada: `maintenance on -until` → esperar as sessões
  lerem o aviso → parar o `serve` → trabalhar → subir → `maintenance off`.

## Consequências

**Impactos positivos:** o modelo passa a ler, no único canal que chega
inteiro até ele, que o backend caiu, desde quando e quando tentar de novo, e
passa a ter uma tool para perguntar. A sessão que começou antes da queda e a
que começa durante veem a mesma lista. O operador anuncia manutenção sem
restart, com linha na trilha, e o SIEM passa a ter a máquina de estados de
cada backend em vez de inferi-la de `upstream gone`.

**Impactos negativos aceitos:**

- **Uma frase nova vai a analistas.** O item 3 diz cada campo e por que pode
  sair; `errors.go` continua sendo o único lugar onde texto vira fio, e o
  teste de vazamento cobre a classe nova com um upstream que devolve a
  credencial no texto do erro.
- **Tool de backend caído continua anunciada, sem prazo.** Escolhido no item
  4; o custo é o modelo tentar e ler "indisponível".
- **O `serve` escreve no banco a cada rodada** (duas tabelas pequenas, uma
  transação por `refresh_interval`, mais uma por transição). Falha de
  escrita não afeta o serviço.
- **Uma leitura de SQLite a mais por chamada** (a tabela de manutenção), no
  mesmo banco e no mesmo custo da leitura do bloqueio.
- **Manutenção lida fail-open.** Um banco ilegível serve como se não
  houvesse manutenção; um backend em manutenção seria discado. Aceito pelo
  argumento do item 6; logado e visível no batimento.
- **O nome `gatte` sai do charset do registro.** Uma entrada existente com
  esse nome deixa de ser servida no primeiro `Reconcile`, com erro de
  `Validate` no log. Nenhuma implantação conhecida usa o nome.
- **`jsonl.Version` vai a 5**; um extrator que recusa versão desconhecida
  precisa ser atualizado.
- **O `until` não encerra nada.** Uma manutenção esquecida continua até um
  `off`; o texto ao analista diz que o horário passou.

**O que não resolve:** timeouts e falhas genéricas continuam erro interno
constante (item 1); o gateway não re-disca mais rápido que o intervalo; a
sessão que começa com o Gatte inalcançável só tem o que o Claude Code diz
mais o `gatte-status`; nada prova o que um processo que controla o host
escreve na trilha (ADR-0017).

## Compliance

- [x] Automatizável? Sim.
- Testes a escrever, cada um visto **falhando no código de hoje** antes da
  implementação quando o comportamento é novo. Os nomes abaixo são o sufixo
  do teste; a implementação os escreve com o prefixo de teste do Go e troca
  esta lista pelos nomes reais (o `TestCitedTestsExist` só aceita nome que
  existe).
  - `internal/gateway`:
    `Refresh_ADeadBackendsApprovedToolsStayListed`,
    `Connect_BootWithABackendDownListsItsStoredApprovedTools`,
    `Refresh_StableListingNeverResurrectsAPendingOrChangedTool`,
    `Refresh_StableListingNeedsAKeptDefinition`,
    `Reconcile_StableListingEndsWhenTheEntryIsRemovedOrUnsigned`,
    `Dispatch_ADownBackendAnswersUnavailableNotInternal`,
    `Dispatch_UnavailableOnlyAfterAuthorizeAndQuarantine`,
    `Dispatch_AGoneMarkedConnectionIsNotCalled`,
    `Dispatch_InFlightDeathAnswersReconnectingAndKeepsTheFailedRow`,
    `Dispatch_MaintenanceAnswersWithoutDialingOrDebiting`,
    `Dispatch_UnreadableMaintenanceServesNormally`,
    `Dispatch_UnavailableCarriesNoUpstreamText` (upstream que devolve a
    credencial no erro),
    `Health_ReconnectingUnlessDialsAreHeldBack`,
    `Health_TransitionsAreAuditedOncePerTransition`,
    `Health_FirstObservationPerProcessIsAudited`,
    `Status_CountsBackendStates`; e as razões novas em
    `TestAuditReasons_AreAStableWireContract`.
  - `internal/gateway/httpapi`:
    `DownBackendCallIsAnIsErrorResultWithTheFixedText`,
    `UngrantedCallerOfADownBackendStillGetsUnknownTool` (byte a byte),
    `GatteStatusIsAlwaysServedAndShowsOnlyTheCallersBackends`,
    `GatteStatusForACallerWithNoTools`,
    `GatteStatusIsAuditedOnce`,
    `InitializeCarriesTheInstructions` (primeira frase, menos de 1.024),
    `GatewayMaintenanceNoticeIsAppendedToEveryResult`,
    `SuspendedFleetAnswers503WithTheConstantText`.
  - `internal/registry`: `Validate_RefusesTheReservedNameGatte`.
  - `internal/health/sqlite`: migração idempotente, ida e volta da
    manutenção, recusa de mensagem com controle, code point escondido,
    quebra de linha ou mais de 200, de `until` no passado ou além de 90 dias.
  - `internal/audit/jsonl`: o esquema exato do batimento na versão 5 e a
    prova de que ele não nomeia backend.
  - `internal/admin` e `adminhttp`: manutenção on/off com linha de operador,
    repetição `changed: false`, `not_found`, `invalid_argument`; overview
    com `serve` `not_reporting`; upstream com `health`; e os dois testes de
    contrato que já existem
    (`TestContract_EveryDocumentedOperationIsServedAndEveryServedRouteIsDocumented`,
    `TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend`),
    que falham a partir do commit deste desenho e passam quando as rotas
    entram.
  - `cmd/mcp-gateway`: `upstream maintenance`, `maintenance`,
    `deregister` apagando manutenção e saúde; script de conexão instalando
    o `gatte-status` sh e PowerShell sem segredo e com valores entre aspas;
    o `gatte-status` sh rodado contra um servidor de teste (200 + 401 → 0,
    porta fechada → 1, 503 com corpo → 3 e o corpo sem controle).
  - `internal/front/gatteweb`: Backends com estado e formulário com CSRF;
    Overview com aviso do gateway e `serve` sem reportar.
- Quando roda: a cada build/CI (`make ci`).

## Notas

- Autor: bunnyiesart + Claude, 29 set 2026, a partir da medição com o
  Claude Code 2.1.285 descrita no Contexto (servidor de sonda, API falsa,
  configuração temporária; nada tocou a configuração real).
- Correções a fazer no commit da implementação: ADR-0024 (as rotas de um
  backend morto não são mais podadas; a conexão marcada não recebe mais
  chamadas; a chamada em voo não é mais `internal error` para o chamador);
  ADR-0012 (linhas `denied` por indisponibilidade e manutenção, a linha do
  `gatte.status` e as linhas `(backend health)`, inclusive `allowed` do
  gateway); ADR-0020 item 4 (suspensão vira `503` com texto constante);
  ADR-0021 (campos do batimento, versão 5); ADR-0040 (rotas de manutenção,
  `health` no overview e nos upstreams, linhas `(maintenance on|off)`,
  contrato 1.1.0); README, *Security model*, com a revelação do item 3.
