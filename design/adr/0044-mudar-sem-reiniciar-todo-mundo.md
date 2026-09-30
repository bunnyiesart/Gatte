# 0044. Mudar sem reiniciar todo mundo: reload, redial e sign -all

**Status:** Accepted — 30 set 2026. Entrou inteiro: o `reload` (SIGHUP,
CLI e `POST /v1/reload`), o `upstream redial` (CLI e `POST
/v1/upstreams/redial`), o `sign -all` e o `sign` como root sem arquivo do
root no diretório do banco. Contrato de gestão `1.2.0`, feature
`serve_control`. Notas de correção nas ADRs 0009, 0020, 0023 e 0040.

## Contexto

A análise de qualidade de vida de 30 set 2026 contou o que um operador
precisava reiniciar, e o que um restart custa aqui. O `serve` é um processo
só (`0001`): reiniciá-lo derruba toda sessão MCP aberta, re-spawna todo
backend e, com o Claude Code, faz cada analista ver o servidor "caído" até o
próximo `/mcp`. Até esta ADR, três coisas rotineiras exigiam esse restart:

1. **Mudar um papel, um grupo ou a quota.** `[[role]]`, `[group_to_role]` e
   `[quota]` eram lidos uma vez, em `buildServer`. A ADR-0009 aceitou
   ("recarregar papéis exige reiniciar o processo (ou um reload
   explícito)") e a correção dela de 28 set registrou que o reload não
   existia.
2. **Fazer uma credencial rotacionada valer.** Desde a ADR-0023 o gateway
   *avisa* que um backend conectado roda com o valor antigo, e a mensagem
   manda reiniciar. Rotacionar a chave de um backend reiniciava os outros
   três. A ADR-0020 (item 6) e a ADR-0023 (§4) deixaram a reconexão sob
   demanda como "a metade do GAB-20 deliberadamente não construída, pelo
   motivo do canal de controle". O mesmo vale para um container que o
   operador reiniciou à mão.
3. **Assinar depois de registrar, e depois de rotacionar a chave de
   assinatura.** `sign` assina uma entrada por vez; rotacionar a chave são
   N comandos. E como a chave é do root, `sign` roda como root, abre o
   banco do usuário de serviço e deixa `-wal` e `-shm` do root no
   diretório dele. O README mandava rodar `chown -R` depois de todo `sign`.
   Quem esquece descobre quando o `serve` não consegue gravar.

O que não pode se perder: o operador aprova exatamente o que viu (aqui:
aplica exatamente o arquivo revisado, e vê quem ganhou e perdeu o quê);
dizer o que não é coberto (que chaves NÃO recarregam); os fronts não
acrescentam nem pulam regra (toda ação é da API de gestão, `0040`); e o host
continua leve — nenhum serviço sempre ligado, nenhuma porta nova.

## Decisão

### 1. O canal: uma linha no banco, e o SIGHUP como campainha

A política e as conexões vivem na memória do `serve`, e o backend de gestão
é outro processo que não a enxerga (`0040`, correção da `0041`). Então um
pedido de reload ou de redial é uma **linha na tabela `serve_request`** do
mesmo SQLite (`internal/control`, adaptador `internal/control/sqlite`),
gravada pelo CLI ou pelo `mcp-gateway admin` com o nome do operador e a
marca (`[cli]`, `[ui]`, `[api]`), e o **SIGHUP é só a campainha**: o `serve`
acorda, pega todo pedido pendente em ordem, faz, e escreve a resposta na
mesma linha. Quem pediu espera a resposta lendo a linha.

- O `serve` grava o próprio pid em `serve_process` ao subir (com o instante
  de início do processo em `/proc/PID/stat` no Linux, para não tocar um pid
  reaproveitado por outro processo do mesmo usuário). Quem pede lê esse pid
  e manda `SIGHUP`. Só o usuário de serviço (ou o root) pode sinalizar o
  `serve`, e é o mesmo usuário com que todo comando de operador que grava o
  banco já roda.
- O SIGHUP é tratado desde o começo do `cmdServe`, junto do SIGTERM: a ação
  padrão dele encerra o processo, e um pedido tocado durante um arranque
  lento tem de ficar na fila, não matar o gateway.
- O pedido roda na goroutine do laço de manutenção, a mesma das rodadas: um
  reload nunca corre em paralelo com uma rodada, e o redial usa a própria
  rodada (item 3).
- Um SIGHUP **sem pedido pendente** (`systemctl reload`, `kill -HUP`) é um
  reload atribuído ao sinal: linha `(gateway)` com a marca `[signal]`,
  porque o sinal não diz quem o mandou.
- Um pedido que não pôde ser tocado (pid morto, sem permissão) é fechado na
  hora como recusado (`serve_not_rung`) pelo próprio requerente, e a
  resposta é `serve_not_running`: um pedido que ficasse pendente seria
  executado, de surpresa, no próximo SIGHUP de outra pessoa. Um pedido que
  sobra de um processo que morreu antes de responder é fechado pelo próximo
  `serve`, ao subir, como `superseded_by_restart`: o restart leu o arquivo
  inteiro e discou todo backend.

**Por que não `POST /v1/reload` direto no `serve`.** Seria um listener novo
no processo que guarda toda credencial — um socket de controle, com dono,
modo e as defesas da `0040` §1 a reescrever — só para entregar uma
campainha. O backend de gestão já é a superfície de controle, sob demanda e
sem porta; ele grava a linha e toca. `POST /v1/reload` existe, sim, mas no
socket do operador, como toda outra ação (`0040` §3): o CLI, o front do
Gatte e o front de uma empresa chamam a mesma regra. Por que não um
arquivo de pid: o do rc.d é do supervisor `daemon(8)` (`deploy/gateway-jail`),
e o `serve` não tem outro; o banco já é o lugar que os dois processos
compartilham.

### 2. Reload: `[[role]]`, `[group_to_role]` e `[quota]`, e nada mais

`mcp-gateway reload` (e `POST /v1/reload`, e SIGHUP) faz o `serve` reler o
**próprio** `-config` e:

1. **Carregar e validar o arquivo inteiro primeiro**, com o mesmo
   `config.Load` do boot (chave desconhecida, papel indefinido, grant
   malformado, quota inválida). Se falhar, nada muda, a resposta é
   `refused` com `invalid_config`, e a linha `(config reload)` é `denied`.
2. **Conferir a nova quota contra o registro**, com o mesmo
   `CheckQuotaCoverage` do boot. Discordando, `quota_mismatch` e nada muda:
   um reload não põe o gateway num estado que o mesmo arquivo teria
   recusado no boot. Registro ilegível: `registry_unavailable`, porque a
   concordância não pode ser conferida.
3. **Trocar a política e a quota de uma vez** (`Gateway.ApplyPolicy`): dois
   ponteiros atômicos, trocados sob o lock da tabela, e no mesmo passo as
   rotas que a nova quota deixa sem declaração são retiradas, como o
   `Refresh` retiraria — entre o reload e a próxima rodada nenhuma tool de
   um backend recém-orçado é servida sem contagem. `ListTools` lê o
   ponteiro uma vez por listagem: nenhuma lista é metade de uma política.
   Uma chamada já autorizada termina sob a política que a admitiu.
4. **Escrever `(config reload)`** com o diff de alcance, e responder o
   mesmo diff: por papel, as tools que ele **ganhou** e **perdeu**, medidas
   sobre as tools que o gateway roteia agora (aprovadas ou não: aprovar é
   outro eixo); os grupos que mudaram de papel; as contas de quota
   adicionadas, removidas ou alteradas; e — sempre — as chaves que diferem
   do arquivo com que o processo subiu e que **não** foram aplicadas.
   Depois roda uma rodada fora de hora, para que a retirada de rotas e o
   resto da manutenção sigam a quota nova.

**O que não recarrega, e é dito:** `listen`, `[oidc]` (issuer, audiência,
claim de grupos), `[signer]` — `trusted_keys` inclusive —, `[vault]`,
`[audit]`, `[telemetry]`, `[response]`, `[oci]`, `[upstreams]`,
`[quarantine]`, `database` e o resto. `trusted_keys` fica de fora de
propósito: é a âncora contra quem grava o banco (`0010`), e trocá-la num
processo vivo é a decisão que merece o restart e a sua linha `boot` no
SIEM. Listen, TLS e IdP mexem no que o processo é, não no que ele permite.
Cada uma dessas chaves que difere aparece em `not_reloaded`, na resposta, no
aviso `not_reloaded` e na razão da linha ("NOT applied until restart: …"),
e continua aparecendo nos reloads seguintes até o restart, porque o
processo guarda o arquivo com que subiu e só troca a parte recarregável.
Chaves que o `serve` nunca lê — `signer.key_file` (só o `sign`, a cada
execução), `[idp]`, `[connect]` e `[admin]` (o backend de gestão, a cada
requisição) — não são listadas: mudá-las não pede restart de ninguém.
As instructions para o analista não entram: nesta versão não há chave de
configuração para elas.

**O cliente não fica sabendo sozinho.** O endpoint MCP é stateless, o
Claude Code busca `tools/list` só ao conectar (medido na
2.1.285), e não há `notifications/tools/list_changed` para mandar. Uma tool
que um papel perdeu é recusada já na próxima chamada; uma tool que um papel
ganhou só aparece para o analista depois de reconectar (`/mcp`). A resposta
do reload diz isso.

**Quem pode dar reload:** quem pode pedir pelo socket do operador ou rodar
como usuário de serviço. O reload não escreve política: aplica o arquivo que
o root escreveu e alguém revisou (`0009` §2). Quem edita o `config.toml`
decide; o reload só faz valer — inclusive uma edição que ainda não era para
valer, e por isso a resposta mostra o diff inteiro.

### 3. Redial: derrubar e discar de novo um backend

`mcp-gateway upstream redial NAME` (e `POST /v1/upstreams/redial`) faz o
`serve` marcar a conexão viva daquele backend como a de um processo morto
(`Gateway.Redial`) e rodar uma rodada fora de hora. A partir da marca o
backend deixa de estar vivo — uma linha `(backend health)` `denied` com a
causa `redial`, e as chamadas dele respondem "reconnecting" (`0041`) —; a
rodada fecha a conexão e disca de novo **pela mesma regra que re-disca um
processo morto** (`0024`), resolvendo o cofre como ele está agora (`0023`),
e o processo novo só recebe chamada depois de listado (`0041` item 4). A
resposta vem depois da rodada, com `live` e a causa, e a linha
`(upstream redial)` diz se havia conexão e se o backend voltou.

- Um backend servível sem conexão viva não é marcado: a rodada o disca de
  qualquer jeito (`was_connected: false`).
- Recusado com `held_back` enquanto as discagens estão congeladas (quota e
  registro discordam, `0030`): o backend seria fechado e não voltaria.
- Recusado com `not_servable` para um nome que o `serve` não considera
  servível; um nome que o registro não tem é `not_found` antes de qualquer
  pedido ser gravado.
- Os outros backends não são tocados: é uma rodada comum, e uma rodada
  deixa quieto quem está vivo e inalterado (`0020`).

Isso fecha a metade do GAB-20 que a `0020` e a `0023` deixaram aberta: a
reconexão sob demanda existe, por um canal de controle que não é um
listener, e só quando um operador pede. O aviso de drift continua, agora
apontando para `upstream redial`.

### 4. `sign -all`, e `sign` como root sem arquivo do root no banco

- `sign -all` assina toda entrada registrada que **não** está validamente
  assinada pela chave configurada: sem assinatura, inválida (a entrada
  mudou depois de assinada, ou a chave não é confiável) ou assinada por
  outra chave — este último é o caso da rotação. Uma entrada já assinada
  por esta chave fica quieta. Cada entrada assinada é impressa com os
  campos que a assinatura cobre, como o `sign NAME` já fazia, e `-dry-run`
  lista sem assinar: o operador vê o que assina. Uma entrada que o dialer
  ou a regra de stdio com credencial recusariam não é assinada, e o comando
  sai com 1.
- Rodado como root, `sign` lê a configuração e a chave como root (as duas
  são do root) e **vira o dono do diretório do banco** (`setgroups`,
  `setgid`, `setuid`) **antes de abrir o banco**. O SQLite cria `-wal` e
  `-shm` como o usuário de serviço, e o root nunca abre arquivo num
  diretório que esse usuário grava — a regra que a `0040` §1 fixou para o
  backend de contas, agora também para o `sign`. Diretório do banco que é
  link simbólico é recusado; diretório do root não tem para quem baixar e
  fica como está. O `chown -R` do README sai.

### 5. Onde cada coisa entrou

- `internal/control` (portas `Store` e `Requester`) e
  `internal/control/sqlite` (`serve_process`, `serve_request`), migrado
  pelo `openStore`.
- `internal/reload`: o diff (`Diff`, `NotReloaded`, `Summary`), puro.
- `internal/gateway`: `ApplyPolicy`, `Policy`, `RoutedTools`, `Redial`,
  `BackendState`; `policy` e `quota` viraram ponteiros atômicos; causa de
  saúde nova `redial`.
- `internal/admin`: `Reload`, `Redial`, `ServeRequest`, e as linhas
  declaradas `(config reload)` e `(upstream redial)` — escritas pelo
  `serve`, que é onde a mudança acontece.
- `cmd/mcp-gateway`: `reload`, `upstream redial`, `sign -all [-dry-run]`,
  o tratamento do SIGHUP (`serve_control.go`) e o toque (`ring.go`).
- Contrato `1.2.0`: `POST /v1/reload`, `POST /v1/upstreams/redial`, `GET
  /v1/serve-requests/{id}` (para um pedido respondido `pending`), código de
  erro `serve_not_running`, feature `serve_control`. O backend espera até
  20 s pela resposta, dentro do prazo de 25 s da requisição; o CLI espera
  `-wait` (padrão 2 min).
- `examples/systemd/mcp-gateway.service` com `ExecReload=mcp-gateway
  reload`, que espera a resposta: um arquivo que o `serve` recusa faz o
  `systemctl reload` falhar. O rc.d da jail ganhou `reload` pelo mesmo
  comando (o `reload` padrão do rc.subr mandaria SIGHUP ao supervisor).

## Alternativas

| Opção | Por que não |
|---|---|
| Recarregar a configuração inteira | `listen`, IdP e `trusted_keys` mudam o que o processo é e contra quem ele se protege; trocá-las a quente é o tipo de decisão que merece o restart e a linha `boot` no SIEM. |
| Vigiar o `config.toml` (inotify/kqueue) | Uma edição salva pela metade viraria política; e o operador perderia o momento de ver o diff. |
| Socket de controle no `serve` | Listener novo no processo que guarda toda credencial, para entregar uma campainha. |
| Arquivo de pid | O do rc.d é do supervisor `daemon(8)`; o banco já é o lugar comum dos dois processos. |
| Reconexão automática ao ver drift | Re-discar um backend no meio de um incidente é decisão do operador (`0023` §4); agora ele tem o comando. |
| `sign` como root com `chown` no fim | O root abriria e mudaria o dono de arquivo num diretório que o usuário de serviço grava — o `-wal` trocado por um link para `/etc/shadow` da `0040` §1. |

## Consequências

- Mudar papel, grupo ou quota é editar o arquivo e `reload`; a trilha
  ganha `(config reload)` com quem ganhou e perdeu o quê, e um SIEM que
  conta linhas de operador vê dois tipos novos.
- Rotacionar a credencial de um backend é `sops` e `upstream redial NAME`;
  os outros backends e as sessões dos analistas não caem.
- Rotacionar a chave de assinatura continua exigindo **dois** restarts
  (`trusted_keys` não recarrega): um para confiar na chave nova ao lado da
  velha, outro depois de tirar a velha; entre eles, `sign -all`.
- `sign` como root não deixa mais arquivo do root; um banco que já tem
  `-wal` do root de antes precisa de um `chown` uma última vez, e o `sign`
  diz isso quando não consegue abrir.
- O `serve` ganha duas tabelas pequenas e nenhuma goroutine: o SIGHUP
  entra no `select` do laço que já existia.

## O que não resolve

- O analista não vê uma tool nova sem reconectar: não há notificação de
  lista mudada num endpoint stateless.
- Fora do Linux o pid é tocado sem a conferência do instante de início; um
  pid reaproveitado por outro processo do usuário de serviço receberia o
  SIGHUP (o `serve` estando morto, o que o `Overview` já mostra como
  `not_reporting`).
- A linha de um `systemctl reload` nomeia o usuário de serviço (`[cli
  env]`); para o próprio nome, `sudo -u mcpgw mcp-gateway reload`.
- `trusted_keys`, `listen`, `[oidc]`, `[vault]` e o resto continuam
  pedindo restart, e a resposta diz quais diferem.
- O `serve` relê o **seu** `-config`; um `mcp-gateway admin` apontado para
  outro arquivo valida um e o `serve` aplica o outro. As unidades de exemplo
  usam o mesmo caminho, e um teste de fitness confere o `ExecReload`.
- Não exercitado ainda: o `sign` como root de verdade (a troca de uid) e o
  `systemctl reload` numa VM Linux; os testes trocam o `setuid` por um
  dublê.

## Testes

- `internal/gateway`:
  `TestApplyPolicy_ANewRoleTakesEffectOnTheNextCallWithoutARestart`,
  `TestApplyPolicy_RefusesAQuotaPlanTheRegistryDisagreesWith`,
  `TestApplyPolicy_WithholdsANewlyBudgetedBackendsUndeclaredToolsAtOnce`,
  `TestApplyPolicy_ListToolsReadsOnePolicy`,
  `TestRedial_DropsAndReDialsOneBackendWithTheCurrentCredential`,
  `TestRedial_RefusesWhatItCannotBringBack`.
- `internal/reload`:
  `TestDiff_NamesWhoGainsAndLosesWhichToolAndNothingElse`,
  `TestNotReloaded_SaysWhichKeysNeedARestart`,
  `TestSummary_IsBoundedAndStaysValidUTF8`.
- `internal/control/sqlite`: `TestRequests_SubmitPendingFinish`.
- `internal/admin`:
  `TestServeControl_AnUnansweredRequestIsPendingAndCanBeReadBack`,
  `TestServeControl_ARequestThatCannotBeRungIsNotLeftPending`.
- `cmd/mcp-gateway`:
  `TestReload_AppliesRolesWithoutARestartAndSaysWhatNeedsOne`,
  `TestReload_AnInvalidFileChangesNothingAndIsRecordedAsRefused`,
  `TestReload_ABareSIGHUPReloadsAndIsAttributedToTheSignal`,
  `TestRedial_ThroughServeIsAnsweredAndRecorded`,
  `TestReload_WithoutServeNothingIsFiledAndAStaleRequestIsSuperseded`,
  `TestRingServe_SignalsOnlyTheProcessThatRecordedItself`,
  `TestCmdReload_PrintsTheAnswerAndExitsByOutcome`,
  `TestCmdSign_AllSignsWhatNeedsItAndLeavesTheRest`,
  `TestCmdSign_AsRootDropsToTheDatabaseOwnerBeforeOpeningIt`.
- `pkg/adminapi`:
  `TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend`
  cobre as três rotas novas.
- `internal/fitness`: `TestSystemdUnits_TheGatewayReloadsTheFileItServes`.
- Quando roda: a cada build/CI (`make ci`).
