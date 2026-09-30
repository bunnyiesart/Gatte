# 0030. Quota por analista, por conta de terceiro

**Status:** Accepted — 28 set 2026.

## Contexto

Toda entrada do registro compartilha uma credencial entre todos os
analistas; é o único modo que este gateway tem. Um backend de threat intel
carrega chaves de terceiros com orçamento finito (VirusTotal, Shodan,
abuse.ch), e um analista em laço queima a cota do time inteiro sem que o
gateway saiba: o `429` do provedor chega ao processo do upstream, responde
sobre a chave compartilhada e não diz quem foi.

A linha interna de onde este repositório foi higienizado resolveu isso no
seu `0021` (modo de credencial **e** quota por analista), que nunca foi
publicado aqui — neste repositório o `0021` é outro documento. Este ADR traz
a metade da quota na convergência de 28 set 2026. A numeração das decisões
abaixo segue a do documento de origem, para que as citações no código
(`ADR-0030 decision N`) continuem apontando para o mesmo argumento.

## Decisão

### 1 e 2. Modo de credencial — **não portadas**

A origem acrescentava `CredentialMode` à entrada do registro (`shared`, e
`dedicated` recusado) e o levava ao hash assinado (`canonical/v3`). Aqui não
existe esse campo: toda entrada é compartilhada, que é exatamente a premissa
de que uma contagem por analista depende. Portar o campo exigiria reassinar
toda entrada para declarar a única opção que existe.

### 3. A unidade contada é a conta no provedor

Nem o upstream (boa parte das ferramentas de um backend de threat intel não
gasta conta nenhuma), nem a ferramenta (um `lookup_ip` pode disparar várias
contas; `decode` nenhuma), nem a variável de ambiente (três variáveis podem
guardar a mesma chave `abuse.ch`). Um `[[quota.provider]]` por conta, com as
ferramentas namespaced que a gastam.

### 4. O limite é política (TOML); o contador é estado (SQLite)

Mesmo critério do `0009` §2. O esquema da tabela `quota_counters` não tem
coluna para limite. `limit` e `window` ausentes, zero ou negativos são
recusados na carga. A janela é fixa, alinhada por truncamento em UTC; o pior
caso por analista é `2 x limit` por janela, e o dimensionamento é orçamento
÷ (2 × analistas). O `Config.Validate` exige ferramenta namespaced, do
upstream da conta, e conta declarada uma vez só.

O cruzamento com o registro é `gateway.CheckQuotaCoverage`, uma função só,
com três chamadores: `Connect` (fatal — `ErrQuotaMisconfigured`, o processo
não sobe), `Reconcile` (ver "Reconcile" abaixo) e `mcp-gateway quota list`.
Falha quando uma conta nomeia upstream não registrado, ou quando uma entrada
não orçada declara uma variável de ambiente de uma entrada orçada (decisão
12). Não há cláusula de modo de credencial.

### 5. O gate fica entre `admit` e o registro `allowed`, e debita antes

`lookup → Authorize → admit (quarentena) → quota → record(allowed) → CallTool`.
Depois de `admit`, para uma ferramenta em quarentena continuar
indistinguível de uma inexistente (`0007`). Antes de `allowed`, porque essa
linha diz que a chamada saiu (`0012`). O débito é anterior à chamada e nunca
é estornado: uma chamada que falha no backend debita; uma recusada por quota
não. Uma chamada que custa várias contas é tudo-ou-nada, numa reserva
atômica (`BEGIN IMMEDIATE`, o `_txlock` que `store.Open` já põe no DSN).

### 6. Contador ilegível ou ingravável recusa a chamada

`quota.ErrUnavailable`, razão `quota unavailable`, sem distinção entre ler e
gravar. Um débito seguido de falha na gravação da auditoria recusa a chamada
sem devolver a unidade — contar a mais é a direção conservadora.

### 7. A recusa é `denied`, com razão própria, e a classe não é opaca

Razões `quota exhausted` e `quota unavailable`. O `httpapi` dá a
`quota.ErrExhausted` classe própria (HTTP 429, mensagem constante
`quota exhausted`); o nome da conta e a virada da janela ficam no log do
operador e na trilha, nunca no fio. `ErrUnavailable` é erro interno
genérico: qual store falhou não é da conta de quem chama.

### 8. Não há comando que zere contador

Alargar limite é commit, revisão e restart.

> *Correção, 30 set 2026:* desde a ADR-0044 é commit, revisão e
> `mcp-gateway reload` (ou SIGHUP): o `[quota]` se aplica ao `serve` em
> execução a partir da próxima chamada, sem restart, e um `[quota]` que
> discorda do registro é recusado sem mudar nada. O mesmo vale para o
> "(com restart)" das Consequências.

### 9. Sem `[quota]`, nada muda

O `quota.Gate` é porta obrigatória de `gateway.Config`; sem nenhum
`[[quota.provider]]` ele é montado sobre um plano vazio e **não julga
chamada nenhuma** — nem as que não consegue atribuir, que um plano com conta
recusa. Diverge da origem, onde o gate recusava sujeito vazio mesmo sem
conta: aqui a instalação sem quota se comporta exatamente como antes.

### 10. O operador lê o consumo por uma porta separada

`quota.Store` (reserva, não lê) vai para o Gateway; `quota.Reader` (lê, não
reserva) vai para o console: `mcp-gateway quota list` e `quota usage`. Uma
fitness function impede `internal/gateway` de nomear a porta de leitura.

### 11. Silêncio sobre uma ferramenta não é "ela não gasta nada"

Toda ferramenta servida por um upstream orçado tem de estar cobrada por
alguma conta ou listada em `quota.free_tools`; a que não estiver **não é
roteada** (`ErrQuotaUndeclaredTool`, não fatal).
`withholdUndeclaredQuotaTools` roda sobre toda tabela que `Connect` e
`Refresh` constroem, logo antes de instalá-la — são os dois únicos lugares
que constroem tabela; `Reconcile` só remove rotas.

### 12. Duas entradas com a mesma variável são uma credencial só

Uma entrada orçada e uma não orçada declarando a mesma variável fazem
`CheckQuotaCoverage` falhar.

### Reconcile (específico deste repositório)

Aqui o `0020` disca upstreams com o processo no ar, então um registro que
muda depois do boot chegaria à tabela por fora do único ponto em que a
origem conferia. `Reconcile` roda `CheckQuotaCoverage` a cada rodada, e
enquanto o plano e o registro discordarem:

- **nada é discado** — nem upstream registrado depois do boot, nem entrada
  alterada, nem backend morto a rediscar. O conjunto vivo só encolhe; o que
  já servia continua servindo;
- a entrada não orçada que carrega variável de uma orçada sai do conjunto
  desejado e é **fechada** se estiver viva;
- o erro volta embrulhando `ErrQuotaMisconfigured`, e o laço do `serve` o
  loga em Error a cada rodada.

Um upstream orçado que Reconcile traz de volta chega à tabela pelo `Refresh`
do mesmo tick, que retém a ferramenta não declarada exatamente como no boot.

## Consequências

- Um provedor esgotado derruba as ferramentas agregadoras daquele analista.
- Toda chamada recusada por quota ainda custa uma linha de auditoria.
- Remover ou renomear o upstream orçado com o gateway no ar congela o
  crescimento da frota até o registro ou o `[quota]` (com restart) voltarem
  a concordar. É deliberado: o renomeado gastaria a conta sem contador.
- A tabela ferramenta → contas é estática; nada observa o fan-out real. A
  aprovação de quarentena é o momento de conferi-la.

## Compliance

- `internal/quota`: `TestAdmit_EveryStoreFailureRefusesTheCall`,
  `TestAdmit_AnEmptyPlanJudgesNothing`,
  `TestAdmit_RefusesWhenTheCallCannotBeAttributed`,
  `TestWindowStart_IsTheSameWindowWhateverOffsetTheClockCarries`,
  `TestStore_PortCannotReadOrLowerACounter`,
  `TestReaderIsASeparatePortFromStore`,
  `TestNewPlan_FreeToolsAreDeclaredNotAssumed`.
- `internal/quota/sqlite`: `TestReserve_IsAllOrNothingAcrossAccounts`,
  `TestReserve_ConcurrentCallersNeverOverGrant`,
  `TestReserve_FailsClosedWhateverBreaksTheCounter`,
  `TestSchema_HasNowhereToPutALimit`.
- `internal/gateway`: `TestDispatch_QuotaExhaustedDeniesBeforeTheAllowedRow`,
  `TestDispatch_QuotaRunsAfterQuarantineSoRefusalsStayOpaque`,
  `TestDispatch_EveryQuotaStoreFailureRefusesTheCall`,
  `TestDispatch_ACallThatFailsAtTheBackendStillSpentQuota`,
  `TestDispatch_UnauditableCallStillSpentQuota`,
  `TestConnect_RefusesToServeWhenAQuotaAccountNamesNoRegisteredUpstream`,
  `TestConnect_WithholdsAToolOfABudgetedUpstreamThatNobodyCosted`,
  `TestConnect_RefusesASecondEntryCarryingABudgetedCredential`,
  `TestSecQuota_ConcurrentDispatchNeverOverGrantsAndAuditsEveryAttempt`,
  `TestSecQuota_ToolNameVariantsCannotBypassTheAccount`,
  `TestSecQuota_WindowBoundaryIsExactAndOffsetIndependent`.
- `internal/gateway`, Reconcile:
  `TestReconcile_ABudgetedUpstreamRegisteredAfterBootIsCheckedBeforeItIsServed`,
  `TestReconcile_DoesNotBringUpAnUnbudgetedEntryCarryingABudgetedCredential`,
  `TestReconcile_ClosesALiveEntryThatStartsSharingABudgetedCredential`.
- `internal/gateway/httpapi`: `TestQuotaExhaustedIsItsOwnClass` e os casos de
  quota em `TestDifferentInternalFailuresLookIdentical`.
- `internal/config`: `TestQuotaLimitCannotDisableTheCounter`,
  `TestQuotaToolMustBelongToTheAccountsUpstream`,
  `TestNoQuotaSectionIsAnEmptyPlanAndNotAMissingOne`,
  `TestExampleConfigDocumentsTheQuota`, `TestQuotaFreeTools`.
- `cmd/mcp-gateway`: `TestQuotaList_ReportsARegistryThatDisagrees`,
  `TestQuotaHasNoSubcommandThatLowersACounter`,
  `TestOpenStoreMigratesTheQuotaTable`,
  `TestBuildServer_QuotaPolicyThatDisagreesWithTheRegistryIsFatal`.
- `internal/e2e`: `TestCheckpoint_QuotaStopsOneAnalystWithoutStoppingTheTeam`.
- `internal/fitness`: `TestTheRequestPathCannotReadAQuotaCounter`,
  `TestEveryAdapterMigrationIsWiredIntoTheCompositionRoot`.

> **CORREÇÃO — 30 set 2026 (ADR-0042 itens 2 e 3).** A recusa por quota
> esgotada passa a ser um resultado `isError` com a conta, o limite, a
> janela e o instante do reset, montado de `quota.ExhaustedError` (política
> e aritmética de janela, nenhuma contagem). E o `gatte.status` informa ao
> chamador o próprio uso de cada conta que as tools dele gastam, pela porta
> estreita `quota.SelfReader` (um analista por pergunta), alcançada só por
> `Gate.Standing` com o sujeito verificado da requisição — pinado por
> `TestTheRequestPathReadsOnlyTheCallersOwnQuota`. A proibição de
> `quota.Reader` e `quota.Usage` no caminho da requisição continua.
