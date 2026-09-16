# 0024. Morte de um upstream conectado: o que conta como morto, quem age, e por que re-discar aqui não é a reconexão que o GAB-20 recusou

**Status:** Accepted — 16 set 2026.

## Contexto

Neste gateway, "conectado" quer dizer que o `Gateway` segura um `Upstream`
com aquele nome. Não quer dizer que o processo do outro lado está vivo.

O resultado, com tudo o que foi construído até a ADR-0023 no lugar:

- o subprocesso de um backend morre (crash, OOM, `kill`, contêiner
  reiniciado);
- a entrada no registro **não mudou**, então o `Reconcile` (ADR-0020) olha,
  vê "registrado e conectado, sem mudança", e não faz nada;
- o `Refresh` não consegue listar aquele upstream, mantém as rotas
  anteriores e loga um erro por tick — indistinguível de um backend só
  lento;
- **toda chamada de analista para aquele backend falha** até alguém
  reiniciar o processo inteiro, o que derruba os outros três junto.

Está declarado em aberto em três lugares (`AGENTS.md` §2, o doc comment do
`Reconcile`, e as Consequências da ADR-0020), e a ADR-0020 escreve
literalmente que isso "exige health check de conexão, que este ADR não
constrói e nenhum outro construiu ainda" — o que convida este ADR em vez de
barrá-lo.

## Alternativas

### Opção A — Sonda periódica (ping/health) por upstream

| Prós | Contras |
|---|---|
| Independente do tráfego: detecta morte mesmo sem ninguém chamando nada | I/O novo por upstream por tick, e uma superfície de falso positivo nova: a sonda tem timeout, e timeout não é morte |
| Padrão conhecido | O MCP não tem ping obrigatório; a sonda viraria um `tools/list` — que é exatamente o que o `Refresh` já faz |

### Opção B — Detectar pela falha, sem distinguir causa

| Prós | Contras |
|---|---|
| Trivial: qualquer erro de listagem fecha e redisca | É a armadilha que a ADR-0013 nomeou e que o `verifyEntry` caiu em 15 set: falhar em medir vira evidência de mudança. Um pico de carga vira respawn da frota inteira |

### Opção C — Morte como fato que atravessa o port (escolhida)

| Prós | Contras |
|---|---|
| Zero I/O novo: quem detecta é o `Refresh`, que já chama `ListTools` uma vez por tick, e o `Dispatch`, que já chama por conta do analista | O port `Upstream` ganha uma obrigação: quem sabe que morreu tem de dizer, e só quando souber |
| A distinção mora no adaptador, onde a evidência está (o fluxo do filho acabou), e não numa heurística no domínio | Um adaptador que reportar errado (timeout como morte) faz o gateway respawnar backend saudável — risco concentrado num lugar pequeno e testável |

## Decisão

**Opção C**, em quatro peças.

### 1. `gateway.ErrUpstreamGone` é evidência positiva, nunca dedução

O port passa a dizer: quem **souber** que a conexão acabou embrulha
`ErrUpstreamGone`; quem não souber nunca embrulha, e o comportamento
degrada para o de antes (fica conectado, falhando, até alguém agir). Isso é
degradação permitida, não violação.

No adaptador stdio, e só ali, "souber" tem dois formatos — **medidos contra
um fixture que realmente sai do ar** (`testdata/dyingfixture`), e não
supostos:

- a chamada **em voo** quando o processo morre volta com `io.EOF` puro;
- toda chamada **posterior** volta com `mcp.ErrConnectionClosed`.

O desenho original previa só o segundo. Casar só com ele deixaria o gateway
cego exatamente no evento que o analista vive — a chamada que estava em voo
— e adiaria o reparo para o tick seguinte. Nada além desses dois entra sem
um fixture que o produza.

### 2. O nosso próprio `Close` não é morte, e a guarda de entrada não basta

`ListTools` e `CallTool` checam `u.closed` na entrada, e **isso não cobre o
caso**: a chamada pode passar da guarda, chegar à sessão e estar em voo
quando outra goroutine roda `Close` — que marca a flag e fecha a sessão, de
modo que a chamada volta com o erro de conexão fechada por algo que *nós*
fizemos. Medido enquanto este ADR era desenhado: **194 de 300** chamadas em
voo cruzando um `Close` concorrente reportaram o erro do SDK.

Reportar isso como morte faria o gateway re-discar um backend que a
reconciliação estava deliberadamente aposentando — o operador desregistra,
e o gateway o traz de volta. Então a flag é **relida depois do erro**, e
upstream fechado nunca reporta morte. A propriedade tem teste de corrida
próprio (`TestCallToolDuringCloseIsNotReportedGone`).

### 3. Quem detecta é quem já estava olhando; quem age é o `Reconcile`

O `Refresh` já pergunta `tools/list` a cada upstream conectado uma vez por
tick, e o `Dispatch` já chama por conta do analista — geralmente é ele que
encontra a morte primeiro, porque roda quando alguém trabalha. Os dois
apenas **marcam**; nenhum fecha nada, respeitando a regra do próprio
`Refresh` de não derrubar conexão.

O `Reconcile` seguinte fecha a conexão morta, e aí a regra que já existe —
"registrado e não conectado → disca" — a traz de volta. Nenhuma regra nova
de reparo: a morte só acrescenta um motivo de fechamento à lista que já
tinha "saiu do registro" e "especificação mudou".

**O marcador é ancorado na CONEXÃO, não no nome.** Guardar "casemgmt
morreu" por nome permitiria que uma marca escrita sobre uma conexão
fechasse a substituta dela, numa rodada em que aquele upstream tivesse sido
re-discado por outro motivo. O que se guarda é o objeto `Upstream`, e o
`Reconcile` só age se a conexão viva ainda for aquela.

### 4. Isto não é a reconexão que o GAB-20 recusou, e o argumento é verificável

O GAB-20 recusou duas coisas, e nenhuma é esta:

- **um canal de controle para dentro do processo que segura todas as
  credenciais** — aqui não há canal: nada de fora pede nada, o gateway
  observa uma falha que ele mesmo sofreu ao fazer o trabalho dele;
- **que uma rotação de credencial passasse a valer sem restart** — e aqui
  é preciso ser exato depois da ADR-0023: uma re-discagem **resolve a
  credencial de novo**, então um backend que morre e volta passa a rodar
  com o valor atual do cofre. Isso é consequência de discar, não um comando
  de rotação, e não dá ao operador nenhum jeito novo de forçar rotação: ele
  teria de matar o backend. Fica escrito porque é a fronteira mais fácil de
  atravessar sem perceber.

Um upstream **vivo** continua com o valor que recebeu no dial até um
restart. Essa é a metade do GAB-20 que segue não construída.

## Consequências

**Impactos positivos:** um backend que morre volta sozinho dentro de um
intervalo, sem derrubar os outros três e sem um humano no meio da noite. A
trilha ganha `upstream gone`, distinto de `upstream call failed`, porque
"respondeu mal" e "não está rodando" mandam o operador para lugares
diferentes.

**Impactos negativos aceitos:**

- **Backend em crash-loop vira respawn por intervalo.** Um contêiner que
  morre logo depois de subir passa a ser discado, morto, detectado, fechado
  e re-discado: **cerca de doze spawns por hora por backend** no padrão de
  5 min. É barulhento e é melhor que o estado anterior (falhar para sempre
  em silêncio), mas é um custo real e não uma nota de rodapé. Quem precisa
  parar o ciclo desregistra o upstream, que é a ferramenta que já existe.
- **Contradiz a leitura literal da ADR-0020 item "o que ela deliberadamente
  não faz"**, que recusou fechar um upstream recém-discado que não lista,
  justamente para não respawnar por intervalo. A distinção é a do item 1
  deste ADR: *não listar* não é *ter morrido*. A ADR-0020 ganha bloco de
  correção apontando para cá em vez de ser editada em silêncio.
- **O port ficou mais largo.** Todo implementador de `Upstream` — inclusive
  os fakes dos testes — passa a ter uma obrigação condicional. Mitigado por
  ela ser condicional: quem não sabe, não reporta.
- **`Status().Upstreams` não cai durante o reparo.** Fechar e re-discar
  acontecem dentro da mesma rodada do `Reconcile`, então o batimento da
  ADR-0021 mostra o mesmo número antes e depois. Um desenho anterior
  afirmava que a assinatura de uma morte no SIEM seria esse número caindo;
  é falso, e o sinal está no log e na trilha (`upstream gone`), não no
  contador.

## Compliance

- [x] Automatizável? Sim.
- Onde vivem os testes:
  - `internal/gateway/stdio/stdio_test.go`: `TestADeadChildIsReportedGone`
    (contra um processo que realmente sai do ar, não contra um erro
    injetado) e `TestCallToolDuringCloseIsNotReportedGone` (a corrida do
    item 2, 40 iterações com stagger).
  - `internal/gateway/reconcile_test.go`:
    `TestReconcile_DeadUpstreamIsClosedAndRedialled`,
    `TestReconcile_AnUpstreamThatMerelyFailedToListIsNotRespawned` (timeout,
    cancelamento e erro genérico NÃO são morte),
    `TestReconcile_DeathIsAnchoredToTheConnectionNotTheName`,
    `TestDispatch_ADeadUpstreamIsAuditedAsGone`.
  - `internal/gateway/gateway_test.go`: `reasonUpstreamGone` nas duas listas
    de `TestAuditReasons_AreAStableWireContract`, porque uma razão nova que
    não entra ali sai do contrato que o SIEM consulta sem ninguém notar.
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 16 set 2026, a partir de um desenho
  verificado por dois refutadores. O bloqueio do item 2 veio da
  verificação, não do desenho: o desenho afirmava que a guarda de entrada
  bastava, e a medição mostrou que não.
- Fecha o último item que `AGENTS.md` §2 listava como lacuna declarada de
  produto. O que continua fora: latência, saturação e saúde por upstream
  além de vivo/morto.
