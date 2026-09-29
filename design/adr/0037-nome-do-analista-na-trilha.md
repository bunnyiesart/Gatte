# 0037. Nome do analista na trilha

**Status:** Accepted — 29 set 2026.

## Contexto

A trilha atribui cada linha ao `sub` do token (`audit.Record.AnalystIdentity`),
e isso está certo: o `sub` é estável, o nome não. Mas o Authelia emite o `sub`
como UUID, então o SIEM mostra `caller=95f757fe-0c7b-4272-…` e nada mais.
Responder "quem foi?" durante um incidente exige consultar o IdP à parte, que
é justamente o tipo de segunda fonte que o `0012` quis eliminar da trilha.

O nome já chega ao gateway: `access.Identity.Name`, preenchido pelo adaptador
OIDC a partir de `name` ou `preferred_username`, com o `sub` como último
recurso. Só não era gravado.

## Decisão

1. **`audit.Record.AnalystName`, só para exibição.** Nenhuma decisão, bloqueio,
   filtro ou comparação usa o campo. `AnalystIdentity` continua sendo a
   atribuição, e `audit -subject` continua comparando só com ela. O IdP pode
   deixar o usuário trocar o próprio nome, e um campo editável pelo analista
   não pode decidir nada sobre o analista.

2. **Só quando diz algo.** `audit.DisplayName` apara o nome e devolve vazio
   quando ele está vazio ou é o próprio `sub` (o fallback do adaptador OIDC).
   Pontos de código que o `internal/visible` esconderia são escritos de forma
   visível, e o resultado é cortado em 256 bytes numa fronteira de rune. Ele
   nunca recusa: um nome estranho não pode tornar a chamada inauditável, e
   portanto recusada. `Record.Validate` é a barreira para qualquer outro
   escritor: acima de 256 bytes, UTF-8 inválido ou caractere que não aparece
   é registro inválido.

3. **Um lugar só no gateway.** `Gateway.record` é por onde passam todas as
   linhas de um chamador (`Dispatch`, `auditRefusal`, `auditFailure`,
   `recordPanic`, `RecordRefusedProbe`), e é ali que o nome entra. As linhas
   sem analista ficam sem nome: eventos `(gateway)`, `(unauthenticated)`
   (inclusive o panic sem `sub`) e ações `(operator:…)`.

4. **O nome entra na cadeia sem mudar hash antigo.** Um registro sem nome é
   codificado exatamente como antes, com a tag `mcp-gateway/audit/chain/v1` e
   os mesmos campos. Um registro com nome usa a tag
   `mcp-gateway/audit/chain/v2` e acrescenta o nome, com prefixo de tamanho,
   depois de `SourceAddress`. Acrescentar um campo sempre presente teria
   mudado o hash de toda linha já gravada, e `audit -verify` passaria a
   acusar adulteração em toda trilha existente. Com a tag por registro, uma
   trilha mista (linhas antigas e novas, com e sem nome) verifica, e apagar,
   trocar ou inventar um nome quebra a cadeia como qualquer outra edição.

5. **Armazenamento e cópias.** SQLite ganha `analyst_name TEXT NOT NULL
   DEFAULT ''` pela lista de `ALTER TABLE`; as linhas migradas ficam com `''`,
   que é exatamente o que o hash delas cobre. A linha JSONL ganha
   `analyst_name`, omitido quando vazio, e `jsonl.Version` vai a `4` (o
   batimento não muda de forma, só de `v`, porque as duas formas versionam
   juntas). O GELF ganha `_analyst_name`, omitido quando vazio. `audit -json`
   ganha `analyst_name` (omitempty) e a tabela ganha a coluna `NAME` ao lado
   de `ANALYST`, escapada como os outros textos de terceiros.

## Consequências

- No SIEM, os campos são `analyst_name` (JSONL) e `_analyst_name` (GELF), ao
  lado de `caller` e `_analyst_identity`. Streams, alertas e dashboards que
  atribuem continuam chaveados na identidade; o nome serve para leitura.
- Um usuário renomeado no IdP aparece com o nome novo só nas linhas novas. As
  antigas guardam o nome da época, e é a identidade que liga as duas.
- Linhas anteriores a esta mudança não têm nome e não vão ganhar: preencher
  retroativamente seria reescrever registros assinados pela cadeia.
- Um consumidor do JSONL que recusa versão desconhecida precisa aceitar `v`
  `4`.
- O nome é um dado pessoal a mais no SIEM. O `sub` já identificava a pessoa,
  então a exposição muda de "identificável com uma consulta" para "legível".

## Compliance

- `internal/audit`: `TestChainHash_AnUnnamedRecordHashesExactlyAsBefore`
  (vetor fixado antes da mudança), `TestChainHash_ANamedRecordIsCoveredAndTaggedV2`,
  `TestValidate_AnalystName`, `TestDisplayName`.
- `internal/audit/sqlite`: `TestMigrate_APreNameTrailStillVerifiesAndTakesNamedRows`,
  `TestVerifyChain_AnEditedNameIsReported`, `TestMigrate_BackfillCarriesTheName`.
- `internal/audit/jsonl`: `TestEmittedLineCarriesTheAnalystNameOnlyWhenNamed`.
- `internal/telemetry/gelf`: `TestMessageCarriesEveryRecordField`,
  `TestMessageOmitsEmptyOptionalFields`.
- `internal/gateway`: `TestDispatch_EveryRowOfAnAuthenticatedCallCarriesTheName`,
  `TestDispatch_ANameThatSaysNothingIsNotRecorded`,
  `TestRowsNobodyAuthenticatedForCarryNoName`.
- `cmd/mcp-gateway`: `TestRunAudit_TableShowsTheNameNextToTheSubject`,
  `TestRunAudit_JSONCarriesTheAnalystName`,
  `TestRunAudit_SubjectFilterDoesNotMatchTheName`.
