# 0031. Bloqueio imediato por analista

**Status:** Accepted — 28 set 2026.

## Contexto

O gateway confia no token até o `exp`, e quem decide o `exp` é o IdP.
Revogar o analista no IdP não encurta um token já emitido: um notebook
roubado com sessão viva continua sendo servido pelo tempo de vida inteiro do
token. Até aqui a única resposta imediata era parar o serviço, o que tira o
time inteiro do ar para tirar uma pessoa.

## Decisão

### 1. Um bloqueio é um sujeito, e só isso

Tabela `blocked_subjects` no banco do gateway (`internal/access/sqlite`),
chave primária `subject`, comparada exatamente com o `sub` verificado — o
mesmo valor da coluna ANALYST de `mcp-gateway audit`. Não há bloqueio de
papel nem de upstream: esses já têm alavanca revisada (papéis no TOML,
`tool revoke`, `upstream deregister`). A migração está no mapa de
`openStore`, e `TestEveryAdapterMigrationIsWiredIntoTheCompositionRoot`
exige isso.

### 2. Lido em toda requisição, sem cache entre requisições

`Gateway.AdmitCaller` é chamado pelo `httpapi` logo depois da verificação do
token, antes de qualquer outra coisa, e devolve um contexto que carrega a
admissão daquele sujeito. `ListTools` e `Dispatch` sobre esse contexto
reusam a resposta; para outro sujeito, ou num contexto que não passou por
`AdmitCaller`, leem de novo (`checkBlock`). É uma leitura por chave
primária por requisição HTTP (`TestOneBlocklistReadPerRequest`,
`TestAdmitCaller_AdmissionCoversOnlyThisRequestAndThisSubject`); o bloqueio
vale na próxima requisição, sem reinício e sem sinal
(`TestBuildServer_AccessBlockReachesARunningGateway`). Um bloqueio gravado
com a requisição já admitida vale a partir da seguinte: a admitida termina,
em vez de ser recusada no meio sem linha no trail
(`TestABlockLandingMidRequestNeverRefusesUnaudited`).

### 3. Recusa constante, auditada

O chamador recebe o `403 forbidden` de qualquer recusa, sem
`WWW-Authenticate` e sem nada que diga "bloqueio"
(`TestBlockedSubjectIsRefusedOnTheNextRequest`). O trail recebe uma linha
`denied` com o sujeito, a origem e o motivo `subject blocked`. Uma tabela
ilegível recusa todo mundo como erro interno (`500`), motivo `blocklist
unavailable`: um interruptor que vira passe livre quando a tabela some está
desligado justamente quando alguém tem motivo para sumir com ela. Um cliente
que desconecta durante a checagem é recusado sem linha e sem log de erro,
porque não é falha da tabela
(`TestAdmitCaller_CancelledRequestIsNotReportedAsABrokenBlocklist`).

Essas linhas não têm limite de taxa: um token bloqueado que insiste escreve
uma linha por tentativa, como já escreve um chamador autenticado que sonda
tools recusadas. O limitador do `0027` cobre só falha de autenticação. O
volume termina no `exp` do token, e quem insiste está identificado na linha.

### 4. Console: `mcp-gateway access block|unblock|list`

`-config`, um sujeito, `-reason` opcional. Cada `block` e `unblock` é uma
ação de operador no trail: ANALYST `(operator:NOME)`, Tool `(access block)`
ou `(access unblock)`, alvo `(gateway)`, e o sujeito e a nota no Reason.
`NOME` é `SUDO_USER`, senão `USER`, senão a conta do processo
(`user.Current`). É a conta de login, não a pessoa: no guest operado como
root por chave, ou por um script que limpa o ambiente, toda linha diz
`(operator:root)` ou a conta de serviço, e quem fez vai no `-reason`. É
atribuição, não autenticação: quem roda o comando escreve no banco.

A comparação é exata. O console recusa sujeito com espaço nas pontas,
caractere de controle ou de formato invisível (Unicode Cf, como U+200B), e o
verificador OIDC recusa um `sub` pela mesma regra, para que não entre
identidade que o bloqueio não consiga nomear
(`TestVerifyRefusesASubjectTheKillSwitchCouldNotBlock`). Um `block` de
sujeito que não aparece no trail avisa que pode ser erro de digitação, e
bloqueia mesmo assim (`TestAccessBlock_WarnsWhenTheSubjectIsNotOnRecord`).

A ordem garante que toda falha deixa o sujeito bloqueado: `block` grava o
bloqueio e depois audita (se a auditoria falhar, o bloqueio fica e o comando
sai com 1); `unblock` audita e depois remove (sem auditoria, não desbloqueia).
Bloquear quem já está bloqueado não muda nada e não grava nada.

### 5. O console vira um segundo escritor da cadeia

Cada append lê a cabeça dentro do seu próprio `BEGIN IMMEDIATE` numa conexão
dedicada (`0015` item 3). Quem ordena os dois processos é o lock do arquivo
SQLite, não a memória de nenhum deles.
`TestAccessBlock_ConcurrentWithServeKeepsTheChainIntact` roda o console num
processo separado enquanto este anexa como o `serve`; a cadeia verifica e
nada se perde. Trocar `BEGIN IMMEDIATE` por `BEGIN` faz o teste falhar.

A ação do operador passa pelo mesmo gravador que o `serve` monta: SQLite,
depois a cópia JSONL e a GELF quando configuradas. Sem a cópia JSONL, a
próxima linha que o `serve` enviasse teria um `prev_hash` que o SIEM nunca
viu — o alarme DANGLING do `deploy/gatte-anchor-verify.sh` disparado pelo
próprio operador (`TestAccessBlock_ReachesTheSIEMCopySoTheShippedChainHasNoGap`).

O `busy_timeout` (5 s, `internal/store`) limita quanto um escritor espera
pelo lock, e o handler de espera do SQLite não é justo: sob escrita contínua
do `serve`, o console pode esgotar o prazo e receber `SQLITE_BUSY`. Nada foi
gravado nesse caso, então `access block|unblock` tenta de novo, até quatro
vezes com recuo (`TestAccessBlock_OutlastsAWriterThatHoldsTheLockPastBusyTimeout`).

## Consequências

- Nenhum processo novo, nenhuma dependência nova; uma leitura SQLite a mais
  por requisição HTTP.
- O bloqueio não revoga nada no IdP. O procedimento de incidente é os dois:
  `access block` agora, revogação da sessão no IdP em seguida.
- Quem constrói `gateway.Config` precisa passar `Blocklist`; `New`
  recusa um nil, porque nil significaria "ninguém pode ser bloqueado".
