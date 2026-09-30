# 0042. Honestidade com o analista: recusas acionáveis, instructions e escopos OAuth

**Status:** Accepted — 30 set 2026. Implementado junto com este desenho, com
notas de correção nas ADRs 0014, 0025, 0030, 0031, 0035 e 0041 (abaixo, em
*Notas*).

## Contexto

A análise de qualidade de vida de 30 set 2026 leu o Gatte do lado do
analista, com o que a ADR-0041 mediu sobre o Claude Code 2.1.285 como
premissa: a lista de tools é lida só no connect; de um erro JSON-RPC só o
`error.message` chega ao modelo; o texto de um resultado `isError` chega
inteiro; instructions e descrição de cada tool são cortadas em 2.048
caracteres; um 401 ou 403 marca o servidor como "needs authentication". O
que ela achou, caso a caso:

1. **Escopos OAuth.** O `serve` monta o `httpapi.Config` sem
   `ScopesSupported`: a metadata RFC 9728 não tem `scopes_supported` e o
   desafio do 401 não tem `scope`. Medido neste desenho (servidor falso em
   loopback, `HOME` e `CLAUDE_CONFIG_DIR` temporários, `claude mcp login
   --no-browser`, só lendo a URL de autorização):

   | o servidor anuncia | a configuração do cliente | o Claude Code pede |
   |---|---|---|
   | nada | nada | nenhum `scope` |
   | `scopes_supported` na metadata | nada | exatamente a lista da metadata |
   | `scope` só no desafio do 401 | nada | nenhum `scope` (o `mcp login` vai direto à metadata, sem POST) |
   | nada | `oauth.scopes = "openid groups"` | `openid groups offline_access` |
   | `scopes_supported` | `oauth.scopes` | o da configuração |

   Três detalhes da medição: `claude mcp add` não tem opção de escopo;
   `claude mcp add-json` aceita `oauth.scopes` (string separada por espaço)
   e **descarta em silêncio** `oauth.scope`, que é a grafia que a mensagem
   de migração do próprio cliente recomenda; e com `oauth.scopes` o cliente
   acrescenta `offline_access` por conta própria. Sem escopo nenhum, a
   maioria dos IdPs (o Authelia incluído) emite um token sem o claim de
   grupos — o analista autentica e recebe lista vazia, o sintoma que o
   `config.example.toml` já descreve para um `groups_claim` errado.

2. **Recusas que o modelo não consegue usar.** Quatro decisões do próprio
   gateway sobre uma chamada concedida e aprovada chegavam como texto
   constante sem próximo passo, e o modelo tentava de novo igual:
   - resultado acima de `response.max_bytes`: `internal error` (o `default`
     do `classify`), por decisão da ADR-0014, cujo teste afirmava que o
     cliente não podia saber que o teto existe;
   - prazo por chamada (ADR-0025) estourado: desde a ADR-0041, "the backend
     failed this call", o mesmo texto de um erro do backend;
   - quota esgotada (ADR-0030): `quota exhausted`, sem dizer quando volta;
   - vagas por analista (ADR-0035) cheias: `concurrency limited`, sem dizer
     que é contando todas as sessões dele.

3. **A conta bloqueada.** O 403 da admissão (ADR-0031) tem corpo
   `forbidden`. Medido: o Claude Code mostra esse 403 como `Status: ! Needs
   authentication` e **não mostra o corpo** (`claude mcp get`); o analista
   faz login de novo, o IdP aceita, e o 403 volta.

4. **A tool retirada no meio da sessão.** O modelo guarda a lista do
   connect. Uma tool que sai da vista do analista depois — papel mudado,
   reescrita que foi para revisão, backend desregistrado — responde
   `unknown tool "casemgmt.x"`, que o modelo lê como nome errado e tenta
   variações.

5. **As instructions** (ADR-0041 item 5) só falam de disponibilidade de
   backend. Não dizem por que uma tool esperada falta, que a lista é fixa
   por sessão, nem a quem pedir ajuda; e o `gatte.status` não diz ao
   analista quem o Gatte acha que ele é, nem quanto da quota dele sobra.

O que não pode mudar: nenhum texto derivado de erro chega ao cliente
(`errors.go`); o texto de um upstream nunca é repassado; quem não tem a tool
concedida e aprovada recebe o que recebia, byte a byte; a quarentena não
vira oráculo (ADR-0007); nada novo sempre ligado, nenhum endpoint novo,
nenhum servidor de autorização dentro do Gatte.

## Alternativas

### Escopos

| Opção | Prós | Contras |
|---|---|---|
| A — só metadata e desafio (escolhida) | Medido suficiente no 2.1.285; a mudança de escopo no `config.toml` alcança todo mundo no próximo login; o script de conexão não muda | Depende de o cliente ler a metadata; um cliente que não lê pede nenhum escopo |
| B — o script grava `oauth.scopes` via `add-json` | Independe da metadata | JSON dentro de aspas no sh e no PowerShell 5.1 (que quebra aspas em argumento nativo); o escopo fica congelado na máquina de cada analista até rodar o script de novo; a grafia recomendada pelo cliente é descartada em silêncio, então uma versão futura pode trocar de chave sem aviso |

### A tool retirada

| Opção | Prós | Contras |
|---|---|---|
| A — memória por sujeito do que foi listado (escolhida) | Responde "não está mais disponível" só a quem viu a tool; o resto continua com os bytes do SDK | Estado em memória no `serve`; some no restart |
| B — sessão MCP com estado | Saberia o que *esta* sessão listou | O `httpapi` é stateless por decisão (ADR-0008): nenhuma sessão vale como autenticação |
| C — manter `unknown tool` | Nada muda | O modelo continua tentando nomes |

### A quota do analista no `gatte.status`

| Opção | Prós | Contras |
|---|---|---|
| A — só a política (limite, janela, reset) | Nenhuma leitura de contador no caminho da requisição | O modelo não sabe quanto sobra até bater no limite |
| B — porta estreita que lê um analista por pergunta (escolhida) | "3 de 50 usados" deixa o modelo avisar antes de acabar | É a primeira leitura de contador no caminho da requisição; precisa de argumento e de fitness function (item 3) |

## Decisão

### 1. Escopos: `[oidc] scopes_supported`

Chave nova, opcional, lista de strings. Cada uma é um *scope-token* da RFC
6749 §3.3 (`%x21 / %x23-5B / %x5D-7E`: ASCII visível sem espaço, aspas ou
barra invertida), sem repetição; `config.Validate` e `httpapi.New` aplicam a
mesma regra. O valor vai:

- à metadata RFC 9728 como `scopes_supported` (o campo já existia no
  documento e nunca era preenchido);
- ao desafio de todo 401, como `scope="openid profile email groups
  offline_access"` (RFC 6750 §3, separado por espaço, entre aspas — a regra
  do token garante que não fecha as aspas). O desafio continua constante e
  sem `error`, pela razão do `rejectUnauthenticated`.

O script de conexão **não muda**: continua `claude mcp add` sem escopo, e o
Claude Code pede a lista da metadata (Contexto, 1). Opção A. O desafio leva o
`scope` também, para o cliente que o lê antes da metadata (a spec MCP
2025-11-25 põe o `scope` do `WWW-Authenticate` antes do `scopes_supported`);
o `mcp login` do 2.1.285 não o lê, e a medição não foi refeita no fluxo do
`/mcp` dentro de uma sessão. Sem a chave, nada é anunciado, como hoje.

### 2. Recusas acionáveis

Mesmo desenho da ADR-0041 item 2: um erro tipado no `internal/gateway`
cujos campos são **estado do gateway ou política declarada pelo operador**,
nunca texto de upstream; o texto é montado só em
`internal/gateway/httpapi/errors.go`; o resultado é `CallToolResult` com
`isError: true`, um bloco de texto, `_meta` com a origem `gateway`, e o aviso
de manutenção do gateway anexado como nos outros. Cada texto diz o que
aconteceu, se o pedido tem culpa, e o que fazer, nessa ordem. Os tipos
desembrulham para os sentinelas de antes (`ErrResultTooLarge`,
`context.DeadlineExceeded`, `quota.ErrExhausted`, `ErrConcurrencyLimited`),
então as razões da trilha não mudam.

| caso | tipo | o que sai além do nome da tool/backend |
|---|---|---|
| resultado acima do teto | `ResultTooLargeError` | o teto em bytes |
| prazo por chamada | `CallTimeoutError` | o prazo |
| quota esgotada | `QuotaExhaustedError` (sobre `quota.ExhaustedError`) | a conta, o limite, a janela, o instante do reset |
| vagas cheias | `ConcurrencyLimitedError` | o limite (que é quantas ele tem em voo) |

Os textos, em inglês como o resto do fio:

```
Gatte: the result of "casemgmt.list_cases" was larger than Gatte's limit of 1048576 bytes (1 MiB) for one result, so Gatte did not deliver any of it. The call itself did run at the backend. Narrow the request (fewer results, a shorter time range, fewer fields) and call again; do not repeat it unchanged. If the call changes something at the backend, that change has already happened.
```

```
Gatte: the backend "logsearch" did not answer this call within Gatte's limit of 60s for one call, so Gatte stopped waiting. This limit is Gatte's, not an error in your arguments, and the backend may still have run the call. A narrower request (a shorter time range, fewer results) may finish in time: retry once with it, and if that also times out, tell the user.
```

```
Gatte: your quota on the "virustotal" account is spent: it allows 100 call(s) per analyst every 24h, and this window resets at 2026-10-01T00:00:00Z. Do not retry this tool, or any tool that spends the same account, before then: every such call until the reset is refused the same way and spends nothing. Tell the user when it resets. Tools that do not spend this account keep working.
```

```
Gatte: you already have 4 calls in flight through Gatte, counting every session of yours, and 4 is the limit per analyst. This call was not run and spent no quota. Wait for one of your calls to finish, then retry this one with the same arguments.
```

**Por que cada um pode sair**, sempre só para quem passou por bloqueio,
rota, `Authorize` e quarentena (os passos 0 a 3 do `Dispatch`, que não
mudam):

- *O teto de tamanho.* A ADR-0014 escondia o teto para que ninguém o
  achasse por busca binária nem aprendesse "quais consultas devolvem muito".
  O teto é um número publicado (README, `response.max_bytes`), e "esta
  consulta devolve muito" é um fato sobre dados que este chamador está
  autorizado a ler e teria recebido inteiros com um teto maior. O que o
  silêncio comprava era o modelo repetindo a mesma consulta. O resultado
  continua recusado inteiro, sem um byte do conteúdo; schema violado e
  resultado irrepresentável continuam `internal error`.
- *O prazo.* O chamador mede o tempo da própria chamada; uma que termina
  exatamente em `call_timeout` já dizia o prazo. O texto não diz nada do
  backend além do nome, que está na tool. Um erro JSON-RPC do backend
  continua "failed this call", sem dizer qual; a ADR-0041 juntava os dois,
  e agora só o prazo, que é decisão do gateway, é separado.
- *A quota.* A ADR-0030 já tratava a quota esgotada como exceção à
  opacidade ("o que vaza é a política publicada do operador, não a postura
  do SOC") e deixava conta e reset só no log. O próprio `quota.Provider`
  diz que o nome da conta "aparece na recusa que o analista lê", e o
  `Charge.WindowEnd` existe "para que uma recusa diga ao analista quando
  tentar de novo". Sai o que é política e aritmética de janela; nenhuma
  contagem, de ninguém.
- *As vagas.* É a contagem do próprio chamador, igual ao limite no momento
  da recusa — a política, de novo.

**A conta bloqueada.** O 403 da admissão ganha o corpo constante

```
Gatte refuses requests from this account. Signing in again will not change that: ask the SOC operator.
```

e, com `[analyst] contact` configurado, ` Contact: "..."`. O código **fica
403**: é a resposta certa para "sei quem você é e não deixo" (a separação
401/403 da ADR-0008), um 401 mandaria o cliente buscar outro token para um
sujeito bloqueado qualquer que seja o token, e um 5xx diria "passageiro". O
corpo não diz "bloqueio" nem por quê. Não revela nada novo: a admissão tem
uma única causa de `forbidden` (`access.ErrSubjectBlocked`; a tabela
ilegível é 500), então o 403 já dizia isso a quem lê o código aberto. Como
o Claude Code mostra "Needs authentication" e descarta o corpo (Contexto,
3), o `gatte-status` ganha, no ramo `Needs authentication`, a frase "se
pedir de novo logo depois de você entrar, o Gatte está recusando sua conta:
entrar de novo não ajuda; fale com o operador do SOC" — texto estático, o
mesmo para todo mundo.

**A tool retirada.** O `httpapi` guarda, em memória, por sujeito
verificado, os nomes que cada `tools/list` respondido **a esse sujeito**
carregou (sem o `gatte.status`), com o instante. Uma `tools/call` de um
nome que não está registrado para ele nesta requisição, e que está na
memória dele há no máximo sete dias, recebe — em vez do `unknown tool` do
SDK — o erro JSON-RPC (código do SDK para tool desconhecida, porque a
chamada não chegou a tool nenhuma):

```
Gatte: the tool "casemgmt.delete_case" was in your tool list but is no longer available to you. Do not retry it and do not try other names or spellings for it. Tell the user; if an operator makes it available again, reconnecting the Gatte server lists it again (in Claude Code: /mcp, then reconnect).
```

O mesmo vale para a tool registrada que o `Dispatch` responde como
desconhecida (entrou em revisão entre a listagem e a chamada da mesma
requisição). Revisão de segurança do caminho do `classify`:

- *Nenhum oráculo para nome adivinhado.* A memória só aprende nomes que o
  próprio sujeito recebeu num `tools/list`. Nome nunca listado a ele — de
  outro papel, em quarentena que ele nunca viu, inventado — recebe os bytes
  do SDK, como hoje; o teste compara com um nome inexistente.
- *Nenhuma causa.* O texto é um só para papel mudado, reescrita em revisão,
  backend desregistrado ou tool que o backend deixou de anunciar. "Em
  revisão" nunca aparece nele. O que o chamador aprende — "uma tool que eu
  tinha não responde mais" — ele aprendia com o `unknown tool` de antes,
  na mesma chamada. O teste do rug pull da ADR-0013 afirmava que isso não
  podia se distinguir de um nome inexistente, para não avisar um atacante
  no meio do rug pull; para quem viu a tool funcionar um minuto antes, o
  `unknown tool` já avisava.
- *Nenhum outro sujeito.* A chave é o `sub` verificado da requisição; a
  memória de um não responde pelo outro.
- *A trilha* não muda: a chamada não servida continua gravando a linha
  `denied (not visible to caller)` pelo `RecordRefusedProbe`, uma por
  chamada.
- *Limites declarados.* Em memória (no máximo 4.096 sujeitos, o listado há
  mais tempo sai primeiro), por sete dias, perdida no restart: depois
  disso, a tool retirada volta a ser `unknown tool`. Um backend fora cuja
  tool continua listada pela lista estável (ADR-0041 item 4) não é
  "retirada" — continua recebendo o texto de indisponível.

### 3. Instructions e o bloco "you" do `gatte.status`

**As instructions** (`status.go`) continuam uma constante sem estado, com a
diretiva da ADR-0041 primeiro, e ganham, antes da frase do `gatte-status`:

```
A tool you expected but lack is either not granted to you or awaiting operator review: do not guess other names for it, tell the user. Your tool list is fixed at connect; after an access change, reconnect (in Claude Code: /mcp, then reconnect). gatte.status also shows your name, roles and quota.
```

A constante fica em 1.096 caracteres (teste: abaixo de 1.200). Depois dela,
duas linhas opcionais do operador, de `[analyst]`:

- `contact` — ` To reach the SOC operator: "...".`
- `backend_notes` — ` Your backends, as the operator describes them: casemgmt: "...". ...`,
  **só dos backends de que este chamador tem alguma tool registrada nesta
  requisição**, pela mesma regra do `gatte.status` (ADR-0041 item 5): as
  instructions nunca nomeiam um backend que o `tools/list` do mesmo
  chamador não mostra. Como o SDK copia `ServerOptions` na construção e o
  conjunto servido só é conhecido depois de registrar (o `AddTool` pode
  recusar uma definição), com notas configuradas o `getServer` registra
  primeiro num servidor de rascunho e depois no que serve. Sem notas, uma
  passada só, como antes.

As linhas do operador entram citadas (`strconv.Quote`), como a mensagem de
manutenção; a validação (`config`) exige uma linha, caracteres visíveis
(`internal/visible`), sem `"` nem `\` (então a citação não as aumenta), até
200 runas no contato, até 12 notas de até 160 runas, e 480 runas somando
nomes e notas. Com isso o pior caso aceito fica abaixo de 2.000 unidades
UTF-16 (o que o cliente JavaScript conta), e o `httpapi.New` recusa um
conjunto que passe disso, como segunda linha. As instructions continuam sem
nada do estado: manutenção, contagem de tools pendentes e saúde de backend
não entram.

**Contagem de tools pendentes: não sai.** Dizer ao analista "há 2 tools
suas esperando revisão" diria quais backends reescreveram tools e quando —
postura do SOC, o que a ADR-0007 fecha —, e mudaria com o estado, o que as
instructions não podem carregar. A frase genérica "não concedida ou
esperando revisão" dá ao modelo o próximo passo sem nenhum dos dois.

**O bloco `you` do `gatte.status`.** O objeto ganha `you`, obrigatório no
`outputSchema`:

```json
"you": {
  "name": "Ana Lyst",
  "roles": ["n1-triage"],
  "quota": [
    {"account": "virustotal", "used": 3, "limit": 50, "window": "24h", "resets_at": "2026-10-01T00:00:00Z"}
  ]
}
```

- `name` é o nome de exibição do token (ADR-0037); `roles` são os nomes
  dos papéis do próprio chamador. Nenhum `sub`.
- `quota` lista **só as contas que alguma tool servida a este chamador
  gasta** — o mesmo recorte de sempre: nenhuma conta que a lista dele não
  leva até ela. `used` falta quando a leitura falhou; `gatte.status`
  responde mesmo assim.
- O `note` constante e a descrição da tool dizem que `you` existe e que uma
  conta com `used` igual a `limit` recusa até `resets_at`.

**A leitura de contador.** A ADR-0030 separou as portas: o `Gateway` segura
um `quota.Store`, que reserva e não lê, e uma fitness function proíbe
`quota.Reader`/`quota.Usage` em `internal/gateway`, porque "quanto X gastou"
é resumo do que X está investigando. O "quanto eu gastei" do próprio
chamador não é esse resumo: ele mesmo fez as chamadas. O que tem de
continuar impossível é a pergunta sobre outro analista, e o desenho a
fecha pela forma:

- porta nova `quota.SelfReader` com um método,
  `SpentBy(ctx, analyst, charges) ([]int, error)`: um analista por
  pergunta, um número por conta pedida, nenhum nome na resposta; o
  adaptador SQLite lê por chave primária com `WHERE analyst = ?`;
- só alcançável por `quota.Gate.Standing`, numa cópia do `Gate` feita por
  `WithSelf` na raiz de composição; `Admit` não muda;
- a fitness function nova `TestTheRequestPathReadsOnlyTheCallersOwnQuota`
  exige que `internal/gateway` chame `Standing` em exatamente um lugar e
  com o argumento `c.Identity.Subject` — o sujeito verificado da requisição
  que está sendo respondida — e o teste negativo a vê falhar com outro
  argumento. A regra antiga (`Reader`, `Usage`) fica intacta.

## Consequências

**Impactos positivos:** o analista autentica e recebe os grupos sem o
operador mexer na máquina dele; o modelo lê, no canal que chega inteiro,
por que a chamada não rendeu e o que fazer — estreitar, esperar o reset,
esperar uma vaga, parar de tentar nomes; o analista bloqueado para de
refazer login em círculo (pelo `gatte-status`); as instructions dizem por
que uma tool falta e a quem perguntar; o `gatte.status` diz quem o Gatte
acha que ele é e quanto sobra.

**Impactos negativos aceitos:**

- **Mais texto variável no fio.** Quatro classes novas de texto montado de
  estado e política, todas em `errors.go`, cada campo argumentado no item 2.
- **O teto de tamanho e o prazo deixam de ser segredo** para quem tem a
  tool (item 2, revertendo a ADR-0014 nesse ponto).
- **A primeira leitura de contador no caminho da requisição**, estreita e
  pinada por fitness function (item 3). Uma consulta por conta por
  `gatte.status`.
- **Estado em memória no `serve`** (a memória do que foi listado): pequena,
  limitada, perdida no restart.
- **Com notas de backend, o `getServer` registra as tools duas vezes** por
  requisição. Sem notas, nada muda.
- **O 403 da conta recusada tem texto** que o Claude Code não mostra; o
  alcance real é o `gatte-status` e quem usa `curl`.

**O que não resolve:** o `scope` no desafio não foi medido no fluxo do
`/mcp` dentro de uma sessão; um cliente que não lê a metadata continua sem
escopo; a tool retirada antes de um restart volta a ser `unknown tool`; a
falha dentro do backend continua sem dizer por quê; nada disso muda o que o
modelo faz com um resultado de backend que imita texto do Gatte (ADR-0041).

## Compliance

- [x] Automatizável? Sim, a cada `make ci`.
- `internal/quota/sqlite`:
  `TestSpentBy_AnswersOnlyTheNamedAnalystsCurrentCounters`,
  `TestGateStanding_NamesOnlyBudgetsTheCallersToolsSpend`,
  `TestExhausted_IsTypedAndKeepsItsText`.
- `internal/gateway`:
  `TestDispatch_AnOversizedResultIsTypedWithTheCeilingOnly`,
  `TestDispatch_AnExhaustedQuotaIsTypedWithPolicyAndReset`,
  `TestDispatch_AConcurrencyRefusalCarriesTheLimit`,
  `TestGatteStatus_YouIsTheCallersOwnStandingOnly` e, alterado,
  `TestDispatch_ABackendErrorOrTimeoutAnswersBackendFailedWithoutItsText`
  (o prazo é `*CallTimeoutError`).
- `internal/gateway/httpapi`:
  `TestScopesAreAdvertisedInTheMetadataAndTheChallenge`,
  `TestNoScopesMeansTheChallengeIsUnchanged`,
  `TestNewRefusesAScopeThatIsNotAScopeToken`,
  `TestAnExhaustedQuotaSaysWhichAccountAndWhenItResets`,
  `TestATimedOutCallSaysItWasGattesLimit`,
  `TestAConcurrencyRefusalSaysHowManyAreInFlight`,
  `TestABlockedAccountIsToldSigningInAgainWillNotHelp`,
  `TestAPulledToolIsNoLongerAvailableOnlyToWhoWasListedIt`,
  `TestListedMemoryIsBoundedAndExpires`,
  `TestInstructionsCarryTheContactAndOnlyTheCallersBackendNotes`,
  `TestNewRefusesInstructionsOverTheClientCut`,
  `TestGatteStatusCarriesTheCallersOwnBlock`,
  `TestInstructionsFitTheClientCutAndAreStateless`; e, alterados,
  `TestOversizedResultIsRefusedWholeAndTheCallerIsToldToNarrowIt`,
  `TestARewrittenToolDisappearsFromALiveSessionWithoutARestart` e
  `TestBlockedSubjectIsRefusedOnTheNextRequest`.
- `internal/config`: `TestScopesSupportedLoadsAndIsOptional`,
  `TestScopesSupportedRefusesWhatIsNotAScope`, `TestAnalystLinesLoad`,
  `TestAnalystLinesRefuseWhatCannotGoInFrontOfAModel`,
  `TestAnalystNotesAreBoundedTogether`.
- `internal/fitness`: `TestTheRequestPathReadsOnlyTheCallersOwnQuota` e
  `TestSelfReadDetectorFailsOnARegression`.
- `internal/admin`: `TestStatusScripts_SayARefusedAccountIsNotALoginProblem`.
- `internal/e2e` e `cmd/mcp-gateway`, alterados para o comportamento novo:
  `TestCheckpoint_OversizedResultNeverReachesTheClient`,
  `TestCheckpoint_QuotaStopsOneAnalystWithoutStoppingTheTeam`,
  `TestBuildServer_AccessBlockReachesARunningGateway`.

## Notas

- Autor: bunnyiesart + Claude, 30 set 2026, a partir da análise de
  qualidade de vida do mesmo dia. A medição do Contexto (itens 1 e 3) usou
  um servidor falso em loopback e o Claude Code 2.1.285 com `HOME` e
  `CLAUDE_CONFIG_DIR` temporários; ao trocar a versão suportada do cliente,
  refazer pela receita da ADR-0041 (`lab/README.md`) mais o `claude mcp
  login --no-browser` para os escopos.
- Correções que esta ADR faz em outras, pelo comportamento de hoje:
  ADR-0014 (o resultado acima do teto é recusado inteiro e o chamador é
  informado do teto); ADR-0025 e ADR-0041 item 2 (o prazo estourado tem
  texto próprio); ADR-0030 decisão 7 (a recusa de quota diz a conta, o
  limite, a janela e o reset; a leitura do próprio contador no
  `gatte.status`); ADR-0031 §3 (o corpo do 403 diz que entrar de novo não
  ajuda); ADR-0035 (a recusa de vaga diz o limite); ADR-0041 item 5 (as
  instructions ganham as frases e as linhas do operador; o limite de 1.024
  virou 1.200 para a constante e 2.000 no total); ADR-0013 (a tool
  retirada responde "no longer available" a quem a viu listada).
