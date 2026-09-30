# 0043. Revisão em lote por backend e troca de imagem sem perder aprovações

**Status:** Accepted — 30 set 2026.

## Contexto

A análise de qualidade de vida de 30 set 2026 achou dois atritos na
quarentena (`0007`, `0013`, `0032`), os dois do mesmo tipo: o caminho seguro
é tão repetitivo que ensina o operador a não ler.

1. **Um backend novo é N aprovações.** Um backend com quarenta ferramentas
   chega com quarenta pendentes. Pelo CLI são quarenta `tool show` e quarenta
   `tool approve -fingerprint`; pelo console web, quarenta idas à lista, sem
   filtro por backend, e depois de cada aprovação a página de resultado e a
   volta à lista. O que a `0032` pagou — aprovar só o que foi visto — vale
   por ferramenta e continua valendo, mas nada ajudava a ver o conjunto.
2. **Atualizar a imagem de um backend oci zera a quarentena.** Um digest
   novo não tinha caminho próprio: era `upstream deregister`, `register` e
   `sign`. O `deregister` chama `Forget` (`0013` item 2) — e com razão: um
   nome registrado de novo pode ser qualquer coisa, e um substituto com
   definições idênticas herdaria aprovações dadas a outro. O efeito numa
   atualização de rotina é toda ferramenta voltar a `pending`, inclusive as
   que o backend anuncia byte a byte iguais. Quarenta aprovações de texto
   que não mudou é exatamente o treino que a quarentena não pode dar.

O que não se negocia (`PRODUCT.md`): o operador aprova exatamente o que lhe
foi mostrado; não existe "aprovar tudo" às cegas, em nenhum front; um front
não acrescenta nem pula regra (toda ação é uma ação da API de gestão,
`0040`); e o host continua leve.

## Decisão

### 1. Conjunto de revisão por backend, aprovado por manifesto

- **Conjunto de revisão** de um backend é toda entrada dele que espera um
  humano: `pending` ou `changed` (`Tool.NeedsReview`, o mesmo critério do
  "Needs review" da lista). Não inclui `approved`, nem outro backend.
- **Manifesto** é o SHA-256 (`quarantine.Manifest`, tag
  `mcp-gateway/quarantine/review-set/v1`, campos com prefixo de tamanho
  como `Hash`) sobre o nome do backend, o número de entradas e, em ordem de
  nome, o nome, o status, o fingerprint observado e a baseline aprovada de
  cada uma. Vai além de "(ferramenta, fingerprint)" de propósito: a baseline
  é aquilo contra o que o diff mostrado foi desenhado, e o status é o que
  decidiu se havia diff. Um manifesto nunca se confunde com um fingerprint.
- **Aprovar o conjunto** (`quarantine.ApprovedSet`, `Store.ApproveReviewSet`)
  lê as entradas do backend, recalcula o conjunto e o manifesto **dentro da
  transação de escrita** e aprova todas no fingerprint que tinham — ou
  nenhuma, com `ErrReviewSetMoved`, se uma ferramenta entrou, saiu ou mudou
  desde a revisão. É o `ApproveFingerprint` da `0032` para um conjunto: a
  mesma corrida (uma descoberta entre a revisão e a aprovação) fecha do
  mesmo jeito, e o SQLite serializa os escritores, então um `Observe` cai
  antes da leitura (e o manifesto não bate) ou depois do commit.
- **Sem manifesto não se aprova conjunto.** O manifesto só é entregue ao
  lado de toda definição que ele cobre. Não há rota, flag nem botão que
  aprove "o que estiver pendente".
- **API de gestão** (contrato `1.2.0`, feature `tool_review_set`):
  `GET /v1/tools/review-set?server=` devolve cada ferramenta como o
  `reviewTool` (definições, diff, `callable_by`, `review_text`), de uma só
  leitura, com o manifesto, as contagens e os code points ocultos somados;
  `POST /v1/tools/approve-set` com `{server, manifest}` aprova. Novos
  códigos: `manifest_required` (400, com `details.manifest` quando há algo
  esperando) e `manifest_mismatch` (409). Repetir depois de uma conexão
  caída responde `changed: false`: não há mais nada esperando.
- **Trilha:** uma linha `(tool approve)` por ferramenta, com o mesmo texto
  da aprovação individual mais `in review set sha256:M`, e uma linha de
  resumo `(tool approve set)` com backend, manifesto e contagens. Uma busca
  que já alerta em `(tool approve)` continua vendo cada ferramenta. Se uma
  linha falhar, a aprovação vale e a resposta diz `recorded: false` com
  `audit_write_failed`, como em toda mudança (`0040` §3).
- **CLI:** `tool review -server NAME` imprime cada definição como `tool
  show` (escapada por `internal/visible`, com diff das `changed`), quem
  poderá chamar cada uma, o aviso de curinga, o total de code points ocultos
  e o manifesto, e o comando a rodar. `tool approve -server NAME -manifest H`
  imprime o mesmo, da leitura contra a qual o manifesto é conferido, e
  aprova; sem `-manifest` não aprova e mostra o manifesto atual; com um
  conjunto que tenha `changed`, falha de escrita da saída impede a
  aprovação, como na `0032`. `-server/-manifest` não se misturam com
  `-fingerprint SERVER TOOL`.
- **Console web:** a página Tools filtra por backend (a API já aceitava
  `server`) e, com o backend filtrado e mais de uma ferramenta esperando,
  oferece "Review them on one page". Essa página desenha cada definição e
  diff pelos segmentos, como a página de uma ferramenta, e termina num botão
  "Approve these N" que leva o manifesto; um conjunto com caractere oculto
  tira o destaque do botão e diz para aprovar as outras uma a uma. Depois de
  aprovar uma ferramenta, o console abre a próxima que espera revisão (do
  mesmo backend primeiro), com a resposta do backend no topo; uma recusa ou
  uma mudança não registrada continua indo para a página de resultado.

### 2. `upstream update NAME -image REF@sha256:HEX`

- Troca **só a imagem** de uma entrada oci, no lugar (`registry.ImageUpdater`,
  porta própria para que só este comando a alcance), validada como no
  registro (digest obrigatório, regras de rede do dialer). Entrada stdio é
  recusada: o comando dela é o que roda, e trocá-lo continua sendo
  deregister e register.
- **A quarentena fica.** O operador afirma que é o mesmo backend, e as
  regras que já existem tornam isso seguro para o texto: a aprovação é do
  fingerprint de uma definição, então vale só enquanto a imagem nova anuncia
  a definição idêntica. Uma que difere vira `changed` na primeira descoberta
  (linha `denied` na trilha, fora do serviço até revisão), uma nova nasce
  `pending`, e `tool review -server NAME` mostra exatamente essas.
- **Continua exigindo a assinatura do root.** A assinatura cobre a imagem
  (`signer`, `v2-image`), então a assinatura antiga deixa de verificar a
  entrada e o gateway a recusa na próxima reconciliação,
  **independentemente de `signer.require_signed`**, até `sign NAME`. O
  comando não apaga essa assinatura: apagá-la tornaria a entrada "não
  assinada", que com `require_signed = false` seria servida.
- **Trilha:** uma linha de operador `(upstream update)` com as duas imagens
  e as contagens da quarentena mantida. A escrita do registro não depende
  dela; se a linha falhar, o comando diz e sai com 1.
- Se o repositório da imagem também mudou, o comando avisa: manter
  aprovações é para o mesmo backend, e para outro o caminho é `deregister`.

## Consequências

- O fluxo de atualização de imagem no README passa a ser `upstream update`
  + `sign` (como root) + `tool review -server`; o `deregister` continua
  sendo o caminho para um backend que não é o mesmo.
- O contrato vai a `1.2.0`, aditivo. Um front antigo não vê a feature e
  segue aprovando uma a uma; o do Gatte só oferece o lote quando o backend
  lista `tool_review_set`.
- Duas leituras a mais por página Tools (a lista completa, para nomear os
  backends, e `whoami`). Nenhum serviço novo, nada sempre ligado.

## O que isto não cobre

- **Comportamento idêntico.** `upstream update` mantém a aprovação de texto
  idêntico, não de código idêntico: a imagem nova pode fazer outra coisa com
  a mesma descrição. Quem responde por isso é a reassinatura do root, como
  para todo backend aprovado — a quarentena nunca julgou comportamento.
- **Entrada sem assinatura sob `require_signed = false`.** Se a entrada não
  tinha assinatura, não há o que invalidar: a imagem nova é servida na
  próxima reconciliação, e o comando avisa. É a política que essa
  implantação escolheu.
- **Revisão de verdade.** O lote tira cliques, não leitura: o manifesto
  garante que o aprovado é o que a página mostrou, não que alguém leu.
  Quarenta definições numa página são quarenta definições.
- **Conjuntos entre backends.** Um manifesto é de um backend; não há
  aprovação de vários de uma vez.

Testes: `TestApprovedSet_ApprovesAllOrNothing`,
`TestManifest_ChangesWithEverythingShownAndNothingElse`,
`TestApproveReviewSet_ADiscoveryAfterTheReviewApprovesNothing`,
`TestApproveToolSet_ApprovesExactlyTheSetShownAndAuditsEachTool`,
`TestApproveToolSet_ADiscoveryBetweenTheReviewAndTheApprovalApprovesNothing`,
`TestRunToolReview_PrintsEveryDefinitionOfTheSetAndTheCommand`,
`TestRunToolApproveSet_ApprovesTheReviewedSetOnly`,
`TestUI_TheReviewSetPageShowsEveryDefinitionAndApprovesOnlyThatSet`,
`TestUI_ApprovingOneToolOpensTheNextWaiting`,
`TestRepository_UpdateImage_ChangesOnlyTheImage`,
`TestRunUpstreamUpdate_KeepsTheApprovalsOfUnchangedDefinitionsOnly`,
`TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend`.
