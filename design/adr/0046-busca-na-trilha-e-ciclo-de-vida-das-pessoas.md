# 0046. Busca na trilha e ciclo de vida das pessoas

**Status:** Accepted — 30 set 2026. Entrou inteiro: os filtros `tool`,
`server` e `until` da trilha (store, CLI, API e página Audit do front do
Gatte, com paginação e download em CSV e JSON Lines), o bloqueio com fim
(`access block -until`, aplicado na admissão, expiração registrada pelo
`serve`), a exclusão de conta e o offboard no socket de contas. Contrato de
gestão `1.4.0`, features `audit_filters`, `block_until`, `account_delete` e
`offboard`.

## Contexto

A análise de qualidade de vida de 30 set 2026 seguiu uma pessoa do começo
ao fim da vida dela no Gatte e achou quatro buracos:

1. **A trilha não respondia "quem chamou esta tool" nem "o que aconteceu
   entre as 14h e as 15h".** `audit` filtrava por analista, desfecho, origem
   e `-since`; não por tool, não por backend e não tinha limite superior. O
   operador exportava tudo com `-json` e filtrava com `jq`, e a página Audit
   do console nem isso: não havia como levar as linhas a quem pediu.
2. **Uma pessoa que sai era três passos em dois lugares.** Desabilitar a
   conta no socket de contas (`0038`), bloquear o subject no socket do
   operador (`0031`) e lembrar de revogar a sessão no IdP. Quem esquecia o
   bloqueio deixava um token já emitido valendo até o `exp`; quem esquecia a
   conta deixava a pessoa entrar de novo depois do desbloqueio.
3. **Uma conta não saía do arquivo de usuários.** Só dava para desabilitar;
   o arquivo do Authelia acumulava todo mundo que já passou pelo time.
4. **Um bloqueio temporário era um lembrete na agenda.** Afastamento,
   investigação de uma noite: o operador bloqueava e tinha de lembrar de
   desbloquear.

O que não pode se perder: o operador aprova exatamente o que viu (aqui:
escolhe o subject que vai bloquear, não o Gatte por ele); dizer o que não é
coberto (a sessão no IdP, que o Gatte não alcança); texto de terceiros
visível (`internal/visible`) também no arquivo baixado; os fronts não
acrescentam nem pulam regra (toda ação é da API de gestão, `0040`); e o host
continua leve — nenhum serviço novo, nenhuma tarefa agendada.

## Decisão

### 1. Busca na trilha: `tool`, `server` e `until`

`audit.TrailQuery` ganha `Tool`, `Server` (o `TargetUpstream`) e `Until`.
Os dois primeiros são igualdade exata, como `Subject` e `Source`, e vão
para o SQL quando os ids da trilha são contíguos (o caso normal) e para a
comparação em Go quando há buraco (`0040`). `Until` é **exclusivo** e
`Since` inclusivo: `[since, until)`, para que duas janelas vizinhas não
repitam nem percam a linha da fronteira. Os dois são comparados em Go sobre
o instante lido, pelo mesmo motivo de sempre (o texto de `RFC3339Nano` não
ordena como o instante). Um `until` que não é depois do `since` é recusado
(`bad_request`; no CLI, "a janela seria vazia").

- CLI: `audit -tool SERVER.TOOL -server NAME -until TIME`. `-verify` recusa
  os três, como recusa os outros filtros.
- API: `GET /v1/audit?tool=&server=&until=`. **Um backend antigo ignora
  parâmetro que não conhece** e responderia a trilha inteira; por isso o
  front só manda os três com a feature `audit_filters` e, sem ela, recusa o
  formulário em vez de mostrar sem filtro o que o operador pediu filtrado.
- Página Audit do front do Gatte: todos os filtros da API (analista,
  desfecho, tool, backend, origem, de, até, linhas), datas em UTC (a página
  diz), e "Older records" com o `before` que a API devolve em
  `next_before`. Nenhum JavaScript: são formulários GET e links.
- **Download**: `GET /audit/export?format=csv|jsonl` com os mesmos filtros.
  O front pede as páginas à API (5000 por vez, andando com `before`) até
  50 000 linhas, mais novas primeiro; se parou antes do fim, o nome do
  arquivo diz `-first50000` e a página manda estreitar a janela. O JSON
  Lines leva os valores crus, no formato `AuditRecord` do contrato. O CSV
  passa cada célula por `frontkit.CSVCell`: todo code point que a tela não
  mostra escrito como `\u{XXXX}` (um bidi override não inverte a linha na
  planilha, uma quebra de linha não vira uma segunda linha), e uma célula
  que a planilha avaliaria como fórmula — começando com `=`, `+`, `-`, `@`,
  tab ou CR, cru ou já escapado — ganha um apóstrofo na frente. Está em
  `pkg/frontkit` para que o front de outra empresa exporte do mesmo jeito.

### 2. Excluir e fazer offboard, no socket de contas

**Excluir.** `DELETE /v1/accounts/{username}` (`idp.Directory.Delete`, no
`autheliafile` pelo mesmo `tmp+rename` que preserva comentários e ordem).
O mesmo alcance de desabilitar (`0040` §1): root, ou o `[admin]
account_group` só para contas que o Gatte gerencia. Linha `(account
delete)`. A resposta diz o que a exclusão não faz: a trilha guarda toda
linha da pessoa; sessão aberta e token emitido continuam; um bloqueio no
subject fica; e o Authelia devolve **o mesmo subject** a uma conta criada
depois com o mesmo username, que herdaria o bloqueio e se misturaria com a
outra pessoa na trilha — pessoa nova, username novo.

**Offboard.** `POST /v1/accounts/{username}/offboard` com `{"subject",
"reason"}` faz, numa chamada só e nesta ordem:

1. **bloqueia o subject no gateway**, que é a metade que corta uma sessão já
   aberta, com a nota `offboard of account "NOME"`;
2. **desabilita a conta**, que impede o próximo login;
3. escreve `(access block)`, `(account disable)` e um resumo `(account
   offboard)`.

E devolve `remaining`, nunca vazio: revogar as sessões e os tokens no IdP
(o Gatte não os alcança, e toda outra aplicação atrás do mesmo IdP ainda os
aceita), bloquear outro subject se a pessoa usou outra conta, excluir a
conta quando não for mais preciso. A página de resultado do front mostra
isso como "Still to do by hand".

- **O subject é escolhido pelo operador.** O Authelia emite o `sub` como
  UUID e o arquivo de usuários não o contém; ligar conta a subject pelo nome
  de exibição seria decidir sobre o campo que a `0037` proíbe de decidir
  qualquer coisa. A página da conta lista quem a trilha viu (subject e,
  para leitura, o nome) e aceita um subject digitado; nada vem
  pré-selecionado. Sem subject (a pessoa nunca usou o gateway) o offboard só
  desabilita, e `remaining` diz que não há bloqueio.
- **Bloquear é de operador.** O `account_group` recebeu contas, não o kill
  switch. Um offboard **com subject** por um par que não é root exige que o
  kernel diga que ele também está no `[admin] operator_group` (o `admin
  -accounts` lê o grupo nas credenciais do par, como o socket do operador
  faz); senão, `forbidden_peer` e nada muda. Sem `operator_group`
  configurado, só o root faz offboard com subject.
- **O root continua sem abrir arquivo do usuário de serviço.** O bloqueio
  mora no banco do gateway; o `admin -accounts` o coloca por um filho novo,
  `admin -block-writer`, com a mesma receita do `-audit-writer` (uid e gid
  do dono do diretório do banco, sem grupos suplementares, ambiente vazio,
  recusa rodar como root), que lê um bloqueio na entrada padrão, o coloca e
  responde se colocou. Ele só aceita um bloqueio válido e com a marca de um
  ator (`[ui]`, `[api]`...), e não escreve a trilha — a linha é do
  `-audit-writer`, que passou a aceitar `(access block)`, `(account
  offboard)` e `(account delete)`.
- **Meio feito não é erro.** Se o bloqueio não pôde ser colocado, nada
  acontece e a resposta é o erro. Se o bloqueio entrou e a conta não pôde
  ser desabilitada, a resposta é 200 com `changed` e o aviso
  `offboard_incomplete`, dizendo o que falta (`0040` §3: mudança em vigor
  nunca é erro). Repetido, o offboard não muda nada e não grava nada.

### 3. Bloqueio com fim: `access block -until`

`access.Block` ganha `Until`; a tabela ganha `blocked_until` (`''` é "sem
fim", que é o que toda linha anterior queria dizer), guardado em UTC e
largura fixa para que o SQL compare dois como compara instantes.

- **O fim vale na admissão, no instante.** `Blocked`, a leitura que o
  gateway faz a cada requisição, responde "não bloqueado" a partir de
  `Until`; não espera varredura nenhuma. Um fim que não se lê mantém o
  bloqueio (falha fechada, como o resto da `0031`).
- **A expiração fica registrada.** A cada rodada de manutenção (a mesma do
  `Reconcile`/`Refresh`, sem goroutine nova), o `serve` escreve uma linha
  `(access block expired)`, atribuída a `(gateway)`, com o subject, o fim,
  quem colocou, quando e a nota; e **só depois** remove o bloqueio, e só
  aquele (subject e fim iguais), para não apagar um bloqueio recolocado
  entre a leitura e a remoção. Linha que não grava deixa o bloqueio
  listado, e a rodada seguinte tenta de novo. A linha do `(access block)`
  já diz o fim desde o começo (`subject "x" until T: ...`).
- Até a rodada, `access list` e `GET /v1/access/blocks` mostram o bloqueio
  como **expirado** (`expired: true`), e ele não conta em `Overview` nem em
  `People`. `access unblock` limpa um expirado à mão (e grava). Bloquear de
  novo um subject com bloqueio expirado substitui o bloqueio; com bloqueio
  em vigor, não muda nada (o fim em vigor fica: para trocar, desbloquear e
  bloquear).
- `-until` aceita um instante RFC 3339 ou uma duração a partir de agora
  (`8h`), como o `maintenance`; tem de estar no futuro. No front, o campo
  "Ends" da página Access, com a feature `block_until`.

### 4. Contrato `1.4.0`

Aditivo: parâmetros `tool`, `server`, `until` em `listAudit`; `until` em
`BlockRequest`; `until` e `expired` em `Block`; `deleteAccount` e
`offboardAccount` no socket de contas; aviso `offboard_incomplete`; as
linhas `(account delete)`, `(account offboard)` e `(access block expired)`.
Uma feature por capacidade no `whoami`, para o front decidir por ela e não
pela versão: `audit_filters`, `block_until`, `account_delete`, `offboard`.
O front do Gatte esconde o campo ou o botão quando a feature falta.

## Alternativas

| Opção | Por que não |
|---|---|
| Rota de exportação na API (`/v1/audit/export`) | A paginação que já existe dá o mesmo, e o formato do arquivo (CSV, escape, apóstrofo) é de apresentação; um front que queira outro formato não precisa de rota nova. |
| Ligar conta e subject pelo nome de exibição | O nome é declaração do IdP que o usuário pode mudar; decidir quem bloquear por ele é o que a `0037` proíbe. |
| Offboard no socket do operador | O processo do usuário de serviço não pode escrever o arquivo de usuários do root (`0038`). |
| Offboard como duas chamadas compostas pelo front | Cada front teria de lembrar a ordem, o registro e o que sobra; a regra ficaria no front. |
| Deixar o `account_group` bloquear | Entregaria o kill switch a quem recebeu só contas; bloquear é da `0031`. |
| Tarefa agendada (timer) para expirar bloqueios | Serviço novo no host; o fim já vale na admissão, e a rodada que existe registra. |
| Remover o bloqueio expirado na admissão | O caminho da requisição não escreve o bloqueio (`0031`, portas separadas), e a linha de expiração tem de ser escrita antes. |

## Consequências

- A trilha responde "quem chamou esta tool, neste intervalo" no CLI e no
  console, e a resposta sai da página como arquivo.
- Uma saída é um clique e três linhas na trilha, e o operador lê na hora o
  que ficou por fazer no IdP.
- Um bloqueio temporário acaba sozinho; o SIEM vê o começo (`(access
  block)` com `until`) e o fim (`(access block expired)`) — um tipo de
  linha novo, de `(gateway)`, para as regras que contam linhas de operador.
- `admin -accounts` ganha um segundo filho; os dois seguem a regra do root
  que não abre arquivo do usuário de serviço.

## O que não resolve

- **A sessão no IdP.** Nem offboard nem exclusão revogam sessão ou token no
  Authelia; o `remaining` diz isso toda vez.
- **O subject não é descoberto.** O operador escolhe; se a pessoa usou mais
  de uma conta, bloqueia cada subject.
- **A expiração é registrada na rodada, não no instante.** Entre o fim e a
  rodada seguinte (no máximo um `quarantine.refresh_interval`), o bloqueio
  já não vale e ainda aparece como expirado; com o `serve` parado, fica
  expirado até alguém desbloquear. Um bloqueio expirado substituído por um
  novo antes da rodada não ganha a linha de expiração (a linha do bloqueio
  antigo já dizia o fim).
- **O download para em 50 000 linhas.** O nome do arquivo diz; para mais,
  janelas menores ou `audit -json` no host.
- **O filtro de tool é exato.** Sem prefixo nem curinga, como os outros.
- Não exercitado ainda: o `-block-writer` com a troca de uid de verdade numa
  VM Linux; os testes rodam o corpo do filho sem o `setuid`.

## Testes

- `internal/audit/sqlite`: `TestPage_MatchesTheChainPositionsWithAndWithoutAGap`
  (com tool, server e until), `TestPage_UntilIsExclusiveAndSinceInclusive`.
- `internal/access/sqlite`:
  `TestUntil_TheBlockEndsAtTheInstantStatedAndIsListedAsExpired`,
  `TestUntil_AnExpiredBlockIsReplacedAndAnActiveOneIsNot`,
  `TestUntil_RemoveExpiredRemovesOnlyTheRowItWasGiven`,
  `TestUntil_AnEndThatDoesNotParseKeepsTheSubjectBlocked`,
  `TestUntil_ABlockMayNotEndBeforeItBegins`,
  `TestUntil_MigrationKeepsOldRowsAsBlocksWithNoEnd`.
- `internal/idp/autheliafile`: `TestDelete_RemovesOnlyThatAccountAndKeepsTheComments`.
- `internal/admin`: `TestAudit_FiltersByToolServerAndUntil`,
  `TestBlock_AnEndIsInTheFutureIsRecordedAndStopsCountingWhenPassed`,
  `TestDeleteAccount_RemovesAManagedAccountAndRecordsIt`,
  `TestOffboard_BlocksThenDisablesRecordsEachAndSaysWhatIsLeft`,
  `TestOffboard_ADelegatedPeerOutsideTheOperatorGroupMayNotBlock`,
  `TestOffboard_ABlockInForceIsNotHiddenByAFailedDisable`.
- `internal/admin/adminhttp`:
  `TestOffboard_TheAccountsSocketAsksTheKernelWhetherThePeerIsAnOperator`,
  `TestDeleteAccount_IsServedOnTheAccountsSocketOnly`,
  `TestAudit_UntilIsParsedLikeSince`.
- `pkg/frontkit`: `TestCSVCell_GuardsFormulasAndMakesHiddenTextVisible`.
- `pkg/adminapi`: `TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend`
  cobre as duas rotas novas e os filtros.
- `cmd/mcp-gateway`: `TestAdmin_TheBlockWriterPlacesOneOperatorBlock`,
  `TestAdmin_TheBlockWriterRefusesToRunAsRoot`,
  `TestAdmin_TheAuditWriterTakesTheOffboardRows`,
  `TestServe_TheRoundRecordsAnExpiredBlockThenRemovesIt`,
  `TestRunAudit_ToolServerAndUntil`, `TestAccessBlock_UntilThroughTheBinary`,
  `TestUI_AuditFiltersByToolServerAndTimeAndPagesBack`,
  `TestUI_AuditDownloadsAreTheFilteredRowsCSVGuarded`,
  `TestUI_AccessBlockWithAnEnd`,
  `TestUI_OffboardBlocksDisablesAndListsWhatIsLeft`.
- Quando roda: a cada build/CI (`make ci`).
