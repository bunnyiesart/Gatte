# 0020. Reconciliação periódica do registro: a metade que faltava do ADR-0004

**Status:** Accepted — 15 set 2026.

## Contexto

`design/adr/0004-registry-unavailability-failure-mode.md` decidiu, em 31 ago
2026, **falhar fechado com retry curto** quando o `Upstream Registry` não
puder ser lido. Em 09 set 2026 o próprio ADR ganhou um bloco de correção
dizendo que só metade disso existe, e o bloco termina com uma exigência
explícita: *ou implementar a releitura periódica que esta decisão manda, ou
um ADR novo que largue o retry explicitamente e diga por quê* — e não mais
um documento que descreva o retry como se ele existisse.

O estado que esse bloco descreve, reverificado no código antes deste ADR:

- `Gateway.Connect` é chamado uma vez, em `cmd/mcp-gateway/serve.go`, no
  arranque. Falha de leitura no boot é fatal e isso é deliberado
  (`serve.go`: um processo que escuta na porta e não serve nada para
  ninguém é pior que um que se recusa a subir).
- `Gateway.Refresh` roda no ticker, mas o comentário dele diz, corretamente,
  que não lê o registro: um upstream registrado depois do boot é invisível,
  um desregistrado continua sendo servido, e um processo que morreu não é
  re-discado.
- Portanto o cenário que motivou o ADR-0004 — o arquivo SQLite ilegível por
  alguns segundos com o processo no ar — **não tem comportamento nenhum**.
  Não falha fechado durante a janela e não relê depois dela.

Há um segundo efeito que o ADR-0004 não nomeou e que pesa mais que o
primeiro na prática: **a assinatura de uma entrada só é verificada no
`Connect`**. Uma entrada adulterada no banco, ou uma assinatura apagada com
`require_signed` ligado, não tira nada do ar até alguém reiniciar. O controle
que existe para detectar exatamente isso só olha uma vez por processo.

> **CORREÇÃO, 15 set 2026, no mesmo dia.** Este parágrafo e o item de
> "Impactos positivos" diziam *revogar uma chave em `signer.trusted_keys`*
> entre os casos que a reconciliação passa a pegar. **Não pega, e não é
> sobre este ADR:** `signer.NewVerifier` é construído uma única vez em
> `buildServer` a partir do TOML (`cmd/mcp-gateway/serve.go`), não existe
> SIGHUP nem watcher de configuração (`main.go` trata só SIGINT/SIGTERM), e
> `verifyEntry` reusa esse mesmo verifier em toda rodada. Tirar uma chave do
> arquivo continua exigindo restart, como qualquer outra mudança de
> configuração (ADR-0009 aceita isso explicitamente para papéis).
>
> O que a reconciliação de fato passa a pegar dentro de um intervalo é o que
> vive **no banco**: entrada alterada por fora depois de assinada, assinatura
> removida sob `require_signed`, entrada nova não assinada. Que é o suficiente
> para o ganho descrito, mas não é o que estava escrito.

## Alternativas

### Opção A — Largar o retry, com ADR

O argumento honesto está escrito no próprio ADR-0004: a garantia da
quarentena não depende da tabela de rotas, porque `Dispatch` consulta
`quarantine.Get` a cada chamada. O que a tabela velha ainda permite é servir
um upstream *desregistrado*, que é uma classe menos grave.

| Prós | Contras |
|---|---|
| Custo zero; nenhum código novo no caminho que segura todas as credenciais | Não cobre a assinatura: uma entrada adulterada no banco continua servida até o restart, e isso não é "classe menos grave" |
| O comportamento passa a ser escolhido em vez de omitido, que era metade da dívida | Deixa de pé a assimetria que o ADR-0004 chama de pior que ter escolhido: a Opção B, rejeitada, continua sendo o comportamento de fato |

### Opção B — Chamar `Connect` no ticker

| Prós | Contras |
|---|---|
| Uma linha de código; releitura completa a cada tick | `Connect` derruba todas as conexões e refaz todas: corta chamadas em voo e respawna todo subprocesso a cada intervalo. O comentário de `Connect` já diz que é por isso que ele não é o que roda no ticker |
| Nenhum conceito novo | Uma soluço de I/O de um segundo passaria a matar quatro subprocessos, que é um custo maior que o problema |

### Opção C — Reconciliação incremental (a escolhida)

Um passo novo que faz o *conjunto de conexões* corresponder ao registro:
disca o que entrou, fecha o que saiu ou deixou de ser servível, e não toca
no que não mudou.

| Prós | Contras |
|---|---|
| Nenhuma conexão saudável é derrubada; chamada em voo não é cortada por manutenção de rotina | Mais estado: é preciso lembrar de qual entrada cada conexão viva foi discada |
| A verificação de assinatura passa a rodar a cada tick, não uma vez por processo | Um upstream quebrado passa a ser re-discado periodicamente, o que gera log recorrente |
| Cobre com uma regra só três casos que hoje são três buracos: entrada nova, entrada removida e backend que falhou no boot | A janela não fecha: ela passa a ser de um intervalo, como a da quarentena |

## Decisão

**Opção C.** `Gateway.Reconcile` passa a existir e roda no mesmo laço de
`serve` que já roda `Refresh`.

### 1. O que um tick de reconciliação faz

Lê o registro. Para cada entrada, aplica os dois mesmos portões que o
`Connect` aplica — `entry.Validate()` (o contrato do registro, re-checado na
saída do store) e `verifyEntry` (assinatura) — e monta o conjunto desejado.
Então, comparando com o conjunto vivo:

- **entrada presente e conexão ausente** → disca. Isso cobre tanto o upstream
  registrado com o gateway no ar quanto o que falhou de discar no boot: uma
  regra, não duas.
- **conexão presente e entrada ausente, inválida ou com assinatura recusada**
  → fecha, e remove as rotas dela na mesma troca, para que a tabela nunca
  aponte para uma conexão fechada.
- **assinatura que não pôde ser LIDA** (store ilegível, não assinatura
  inválida) → não fecha e não disca: fica como está. Os dois são falhas do
  `verifyEntry` e a primeira versão deste ADR tratava os dois igual, o que
  era um defeito com o nome já escrito em outro ADR — a regra da ADR-0013,
  que o próprio `Refresh` repete: *falhar em medir não é evidência de que
  algo mudou*. O agravante é que o store de assinaturas **é o mesmo arquivo
  SQLite do registro**, então um `SQLITE_BUSY` que o item 3 promete
  sobreviver mantendo as conexões fecharia todas elas por este caminho.
  Fail-closed aqui quer dizer "não comece a servir o que não foi
  verificado", e não "derrube o que já estava servindo".
- **entrada e conexão presentes, com a *especificação* mudada** → fecha e
  disca de novo, nessa ordem. Especificação aqui é o que o `Dialer` recebe
  mais os nomes das variáveis de ambiente: transporte, comando, argumentos,
  URL, `EnvVarNames`. Fechar antes de discar é fail-closed e evita dois
  processos do mesmo backend vivos ao mesmo tempo com a mesma credencial.
- **entrada e conexão presentes, sem mudança** → não faz nada. Este é o caso
  comum e é o que separa esta decisão da Opção B.

Falha ao discar não derruba nada: o upstream simplesmente fica fora, como no
`Connect`, e o próximo tick tenta de novo.

### 2. Reconciliação não monta tabela de rotas; `Refresh` monta

`Reconcile` mexe no conjunto de conexões e só poda as rotas do que fechou.
Descobrir que ferramentas um upstream recém-discado anuncia é trabalho do
`Refresh`, que o laço de `serve` chama logo em seguida, no mesmo tick.

Isto é uma escolha de simplicidade e está aqui para não ser "otimizada"
depois: **um único lugar monta a tabela de rotas a partir das conexões
vivas**. Duplicar essa montagem dentro do `Reconcile` significaria duas
implementações de `mergeRoutes` que precisam concordar sobre colisão de
nomes, e a segunda divergiria da primeira em algum mês.

A consequência, dita em vez de descoberta: chamar `Reconcile` sozinho deixa
um upstream novo conectado e servindo nada. Quem chama os dois é o laço.

### 3. Registro ilegível suspende o fleet, sem matar os processos

Quando a leitura falha, o gateway entra em **suspensão**: a tabela de rotas
é esvaziada, nada é servido, e a suspensão só sai quando uma leitura voltar
a funcionar. É o fail-closed que o ADR-0004 decidiu.

O que muda em relação ao `Connect` é o que *não* é derrubado: **as conexões
ficam de pé**. A decisão do ADR-0004 é "nada é servido enquanto o registro
não puder ser confirmado", não "mate todo subprocesso a cada soluço de
disco". Manter as conexões é o que torna a recuperação barata — que é o
ponto inteiro de existir um retry em vez de um restart.

**A suspensão termina onde o serviço começa, e não na leitura.** Uma leitura
bem-sucedida *confirma* a frota; quem a tira da suspensão é o `swapRoutes`
que instala uma tabela confirmada, logo em seguida, no mesmo tick. A primeira
versão limpava o flag na leitura, e como o `Reconcile` não monta tabela
(item 2) isso abria uma janela — de um `tools/list` por upstream — em que o
gateway se declarava disponível roteando nada, respondendo **e auditando**
como `unknown tool` chamadas a ferramentas que existem. Que é exatamente a
confusão que o item 4 abaixo existe para impedir, reintroduzida três
parágrafos adiante.

### 4. Suspensão é dita ao cliente, não fingida de vazio

Suspenso, `ListTools` devolve `ErrRegistryUnavailable` e `Dispatch` recusa
com o mesmo erro, auditado com `registry unavailable`. Não devolvem lista
vazia nem "tool desconhecida".

Este projeto já aplica essa regra à quarentena ilegível, com a justificativa
de que *uma lista vazia e um store de aprovações quebrado não podem parecer
a mesma coisa para um operador*. Vale igual aqui, e vale mais: suspensão é
exatamente o estado que o `serve.go` chama de pior que não subir — escutando
a porta e servindo nada. Se ele vai existir, tem que ser legível nos dois
lados, no log a cada tick e na resposta ao cliente. Em `httpapi` isso cai em
`classInternal` (500), que é distinto de "não existe essa tool" e não revela
nada sobre o inventário.

### 5. O retry curto é o intervalo curto, e mora no laço

Suspenso, o laço passa a tentar a cada `registryRetryEvery` (5 s) em vez do
intervalo de refresh (5 min por padrão), e **não** chama `Refresh` enquanto
estiver suspenso: nada é servido, então re-observar quarentena pode esperar,
e martelar os backends a cada 5 s durante um incidente de disco é o oposto
do que se quer. É assim que "retry curto, da ordem de segundos" do ADR-0004
vira código, sem inventar uma segunda chave de configuração.

O ritmo fica no laço de `serve`, não no `Gateway`: o `Gateway` continua uma
máquina de estado que faz um passo quando mandam, que é o que torna os
testes desta decisão determinísticos.

### 6. Credencial rotacionada continua não re-discando

`CredentialDrift` segue detecção-pura e o remédio segue sendo restart
(GAB-20). Comparar especificação, e não credencial, é o que mantém essa
fronteira: os dois efeitos são parecidos vistos de fora e são decisões
diferentes. Re-registrar a mesma entrada não conta como mudança — a
comparação é por conteúdo, não por `UpdatedAt` — justamente para que
ninguém passe a usar "toca na entrada" como um comando de reconexão que este
ADR não está autorizando.

## Consequências

**Impactos positivos:** `upstream register` e `upstream deregister` passam a
valer dentro de um intervalo, sem restart — servir ainda depende da
quarentena aprovar aquelas ferramentas, então "vale" aqui quer dizer que o
backend é discado e suas tools observadas, não que elas aparecem para um
analista. Uma assinatura que deixou de verificar **contra o que está no
banco** — entrada alterada depois de assinada, assinatura removida sob
`require_signed` — tira o upstream do ar no próximo tick em vez de no
próximo reinício, que é o ganho de segurança maior deste ADR. Mudar
`signer.trusted_keys` não está incluído: é configuração, lida uma vez no
arranque, e continua exigindo restart (ver a correção no Contexto). Um
backend que falhou de subir no boot volta sozinho quando voltar a discar.

**Impactos negativos aceitos:**

- **A janela não fecha, só passa a existir.** Entre dois ticks, um upstream
  desregistrado continua sendo servido por até um intervalo. Encurtar custa
  uma leitura de registro e um `tools/list` por upstream mais frequentes.
  É a mesma troca do ADR-0013, feita com os olhos abertos.
- **Suspensão é um estado novo em que o processo está vivo e inútil.** É o
  preço do retry. Mitigado pelo item 4 — ninguém descobre isso por dedução.
- **Log recorrente para upstream quebrado:** um backend que não disca gera
  uma linha de erro por tick, não uma por boot.
- **Uma entrada alterada reinicia o subprocesso dela.** Cortando chamadas em
  voo daquele upstream. É o comportamento correto (o processo vivo está
  rodando uma especificação que o operador substituiu), e é diferente do que
  acontecia antes, que era nada.
- **Isto não é verificação de saúde, e a diferença é fácil de não notar.**
  "Conectado" quer dizer que o gateway segura um `Upstream` com aquele nome,
  não que o processo do outro lado está vivo. Um backend cujo subprocesso
  morreu continua no conjunto vivo, com a entrada inalterada, e portanto não
  é re-discado — aparece como um `Refresh` que não consegue listar, uma vez
  por tick, que é o mesmo sinal de um backend só lento. Separar os dois
  exige health check de conexão, que este ADR não constrói e nenhum outro
  construiu ainda.
- **Um upstream recém-discado que não lista as ferramentas fica conectado
  servindo nada**, em vez de ser fechado como o `Connect` faz. Fechá-lo aqui
  significaria respawnar um subprocesso por intervalo enquanto o backend
  estivesse quebrado; o `Connect` fecha porque não tem próxima rodada.

**Trade-offs assumidos:** aceitamos estado novo dentro do `Gateway` (de qual
entrada cada conexão foi discada) em troca de não derrubar conexão saudável.
A alternativa sem esse estado é a Opção B, cujo custo por tick é alto demais
para rodar de rotina.

## Compliance

- [x] Automatizável? Sim — os fakes de registro e dialer já existem em
  `internal/gateway/gateway_test.go` e permitem forçar cada caso.
- Onde vivem os testes: `internal/gateway/reconcile_test.go`.
  - `TestReconcile_PicksUpAnUpstreamRegisteredAfterBoot`
  - `TestReconcile_DropsADeregisteredUpstreamAndItsRoutes`
  - `TestReconcile_LeavesAnUnchangedUpstreamConnected` (a garantia de que
    isto não é a Opção B disfarçada)
  - `TestReconcile_RedialsWhenTheEntrySpecChanges`
  - `TestReconcile_ClosesAnUpstreamWhoseSignatureStopsVerifying`
  - `TestReconcile_RegistryFailureSuspendsWithoutClosingConnections`
  - `TestReconcile_SuspendedGatewayServesNothingAndSaysWhy`
  - `TestReconcile_RecoversAfterTheRegistryComesBack`
  - `TestReconcile_RetriesAnUpstreamThatFailedToDial`
  - `TestReconcile_CredentialRotationAloneDoesNotRedial` (a fronteira do
    item 6)
  - `TestReconcile_ChangedEntryIsClosedEvenIfTheRedialFails`
  - `TestReconcile_SignatureStoreUnreadableKeepsTheFleet` (a distinção do
    item 1)
  - `TestReconcile_RecoveryDoesNotAnswerUnknownToolInTheGap` (a janela que
    o item 3 fechou)

  Três destes existem porque uma revisão adversarial de 15 set 2026 provou,
  **por mutação**, que os testes originais passavam com o comportamento
  invertido: a ordem fechar-antes-de-discar não era observável (o dialer
  falso devolve o mesmo objeto por nome), a guarda do `swapRoutes` podia ser
  apagada sem quebrar nada, e a asserção de que a tabela velha é descartada
  tinha saído junto com a mudança de erro. O dialer falso agora registra
  quantos fechamentos aquele nome tinha em cada discagem, que é o que torna
  a ordem asseverável.
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 15 set 2026, fechando a exigência escrita no
  bloco de correção de 09 set 2026 do ADR-0004.
- O ADR-0004 continua sendo a decisão (falhar fechado com retry curto); este
  aqui é a forma dela. A correção daquele arquivo foi atualizada para
  apontar para cá em vez de descrever uma pendência.
