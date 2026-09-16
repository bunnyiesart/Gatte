# 0021. Batimento operacional na mesma trilha: o que o SIEM precisa ver quando nada acontece

**Status:** Accepted — 15 set 2026.

## Contexto

Duas pendências escritas em lugares diferentes são a mesma pendência.

A primeira está no `AGENTS.md` §2, herdada da lista de "não coberto" da
ADR-0003: **telemetria/observabilidade (OWASP MCP08)** — o `Audit Trail`
responde "quem chamou o quê", não "este processo está saudável agora". Sem
design nenhum até hoje.

A segunda está no `WORKFLOW.md`, no item da âncora externa: *"não existe
alerta no Graylog para 'as linhas pararam de chegar para esta cadeia', que é
a aparência de um shipper morto"*. O `deploy/gatte-anchor-verify.sh` fechou
a metade da comparação de cabeças; esta metade continuou aberta.

**São a mesma porque o alerta que falta é impossível de escrever hoje.** A
trilha só emite linha quando alguém chama uma ferramenta. Um gateway quieto
— madrugada, fim de semana, turno sem incidente — emite zero linhas
legitimamente, então "nenhuma linha nos últimos 30 minutos" não distingue
silêncio saudável de:

- shipper morto (fluent-bit parado, offset DB ilegível, jail sem o caminho);
- gateway morto ou em laço de restart;
- gateway suspenso pela ADR-0020, servindo nada;
- frota vazia porque todo upstream caiu.

O que falta é um **sinal positivo periódico cuja ausência seja detectável**.
E, uma vez que ele existe, ele é também o lugar natural onde as métricas
operacionais que a MCP08 pede cabem — sem inventar um segundo caminho de
saída para o mesmo processo.

## Alternativas

### Opção A — Endpoint `/metrics` no padrão Prometheus

| Prós | Contras |
|---|---|
| Padrão de mercado; dashboards prontos | Exige um Prometheus rodando, com sua própria vida operacional, para um time de ~7 pessoas sem função de plataforma. A `DEVELOPMENT-LOG.md` §10.1a rejeitou uma plataforma inteira exatamente por esse argumento |
| Separa telemetria de auditoria | Pull: quem não é raspado não reclama. Um gateway morto some do dashboard do mesmo jeito que um gateway sem tráfego, que é o problema que viemos resolver |
| — | Superfície HTTP nova no processo que segura todas as credenciais, e a decisão de quem pode raspá-la |

### Opção B — Batimento num arquivo/caminho próprio

| Prós | Contras |
|---|---|
| Não toca no esquema da trilha | **Não prova nada sobre o caminho que interessa.** O shipper da trilha pode estar morto enquanto o do batimento vive; o alerta ficaria verde durante exatamente a falha que ele existe para pegar |
| Um consumidor só lê o que quer | Dois arquivos, dois shippers, duas chances de configurar errado |

### Opção C — Batimento como uma segunda forma de linha, no mesmo arquivo (escolhida)

| Prós | Contras |
|---|---|
| Atravessa o mesmo `tail`, o mesmo shipper, o mesmo `[OUTPUT]` e a mesma stream. A ausência dele **é** a prova de que aquele caminho parou | O arquivo deixa de ter uma forma só de linha, e todo consumidor que hoje assume "toda linha tem `hash`" precisa saber disso |
| Zero dependência nova: nenhum cliente de rede no processo, o que a `jsonl` proíbe explicitamente no caminho de request | Exige migração de consulta no `gatte-anchor-verify.sh`, e a migração tem de conviver com as linhas v1 já indexadas |
| O mesmo tick que já existe (ADR-0013/0020) carrega o batimento | O batimento é escrito pelo gateway: contra quem domina o host, ele vale tanto quanto qualquer outra linha que o gateway escreve, isto é, pouco |

## Decisão

**Opção C.** Uma segunda forma de linha no sink JSONL, emitida a cada tick
de manutenção e uma vez no arranque, e escrita também no log estruturado.

### 1. `v` vai a 2 e toda linha passa a se declarar

`jsonl.Version` vira `2` e as duas formas ganham `type`: `"record"` para a
linha de auditoria, `"heartbeat"` para o batimento. A versão existe
precisamente para isto — o comentário dela já dizia que acrescentar campo é
bump — e um consumidor que não conhece a forma nova pode recusá-la em vez de
interpretá-la errado.

Discriminar por campo declarado, e não por ausência de `hash`, é o que
permite que a terceira forma de linha (se um dia houver) não quebre nada.

### 2. O batimento não entra na cadeia, e não finge entrar

Ele não tem `hash` nem `prev_hash`: não é um `audit.Record`, não passa pelo
SQLite, não é encadeado e não conta como evidência de nada que um analista
fez. Ele **carrega** a cabeça que este processo emitiu por último, no campo
`head`, que é uma afirmação sobre a cadeia e não um elo dela.

Isto respeita o item 1 da ADR-0017 — um `audit.Record`, uma serialização —
em vez de contorná-lo. A alternativa que a 0017 descartou era *montar um
evento próprio para o SIEM com os campos que fazem sentido num SIEM*, ou
seja, uma segunda descrição do mesmo fato. O batimento descreve um fato
diferente: o estado do processo.

### 3. O que o batimento carrega

Conjunto fechado, sem `omitempty`, pela mesma regra da linha de auditoria:

| campo | o que é |
|---|---|
| `v`, `type`, `ts`, `chain` | versão, forma, instante em UTC, cadeia |
| `boot` | instante de arranque deste processo, em UTC |
| `head` | a última cabeça emitida por este processo, vazia se ele ainda não emitiu nenhuma |
| `records` | linhas de auditoria emitidas por este processo desde o arranque |
| `allowed`, `denied`, `failed` | registros que o gateway escreveu, por desfecho, desde o arranque |
| `upstreams` | backends conectados agora |
| `tools` | rotas na tabela agora |
| `suspended` | se a frota está suspensa por registro ilegível (ADR-0020) |

**Acumulados desde o arranque, não deltas.** Um batimento perdido não perde
eventos, e `boot` é o que explica um contador que voltou a zero. Quem quer
taxa faz a diferença no dashboard, que é onde a janela é escolhida.

`boot` é o campo que torna reinício visível, e reinício importa neste
sistema mais do que na maioria: é o que faz uma credencial rotacionada
entrar em vigor (GAB-20) e é o que o `daemon -r` faz sozinho quando o
processo morre.

### 4. Os contadores são contados onde os registros são escritos

`Gateway.record` é o único lugar deste sistema que escreve um registro de
auditoria — `Dispatch`, `auditRefusal`, `auditFailure`, `RecordAuthFailure`
e `RecordRefusedProbe` passam todos por ele. O incremento vai ali, depois da
escrita durável ter dado certo.

Isso dá a estes números um significado exato e verificável: **são as linhas
que este processo escreveu na trilha desde o arranque, contadas por
desfecho.** Não são "chamadas", e a diferença é a que a `jsonl` já
documenta: uma chamada que falhou produz duas linhas, `allowed` e `failed`.
Conte `allowed` para tentativas e leia `failed` como anotação.

Se os contadores e a trilha discordarem, **a trilha está certa**. Ela é
durável e encadeada; estes são inteiros em memória que morrem com o
processo. Eles existem para dizer "algo está acontecendo" num intervalo, não
para serem a fonte de verdade de nada.

### 5. O alerta que isto habilita, e a frase honesta sobre ele

No Graylog: *nenhuma mensagem com `type:heartbeat` para `chain:<nome>` nos
últimos N minutos* → o gateway parou, ou o shipper parou, ou a jail sumiu.
Com N igual a três vezes o `quarantine.refresh_interval`, um tick perdido
não acorda ninguém e dois acordam.

O que este alerta **não** prova: nada contra um atacante que controla o
host. As linhas não são assinadas — a `0017` já diz isso da trilha inteira —
então quem escreve o arquivo pode escrever batimentos. O que ele pega é a
falha operacional: processo morto, shipper morto, disco cheio, jail parada.
Que é a falha que efetivamente acontece.

### 6. Durante a suspensão, o batimento não segue o tick

Suspenso, o laço passa a rodar a cada 5 s (ADR-0020 item 5). Um batimento por
tick ali seriam **720 linhas por hora**, no mesmo arquivo, no mesmo disco e na
mesma stream — durante o incidente de I/O que causou a suspensão, e
falsificando de quebra as duas coisas que este ADR escreve: o custo de "doze
mensagens por hora" e a janela de alerta medida em intervalos de refresh.

Então: o primeiro batimento de uma suspensão sai na hora, porque **ele é o
sinal**; os seguintes saem na cadência normal (`refresh_interval`) enquanto o
estado não mudar. Sair da suspensão também é mudança de estado e também sai na
hora.

### 7. Sem SIEM configurado, o batimento continua existindo

Ele vai para o `slog` em toda rodada, tenha ou não sink — mas **não com os
mesmos campos**, e a diferença é deliberada: sem sink não há `chain`, `head`
nem `records`, porque os três descrevem um sink que não existe, e sai
`uptime` no lugar de `boot`, que é a forma legível num log local. Reportar
`records: 0` para um processo que atendeu o dia inteiro seria pior que
omitir.

O operador sem Graylog perde o alerta e perde a cabeça da cadeia; mantém os
contadores, o estado da frota e a suspensão. Esta seção dizia "com os mesmos
campos" até 15 set 2026.

## Consequências

**Impactos positivos:** passa a existir um sinal positivo periódico, e
portanto um alerta possível, para a falha que hoje é indistinguível de
silêncio. A MCP08 sai de "sem design" para "coberto no tamanho deste
sistema", com o escopo dito. Reinício, suspensão e frota vazia ficam
visíveis no mesmo lugar em que o SOC já trabalha.

**Impactos negativos aceitos:**

- **O arquivo deixou de ter uma forma só.** Todo consumidor que assumia
  "toda linha tem `hash`" precisa filtrar. O `gatte-anchor-verify.sh` é um
  desses e foi corrigido junto: a consulta passa a excluir batimentos, e
  **pela negativa** (`NOT type:heartbeat`) e não pela positiva
  (`type:record`), porque as linhas v1 já indexadas no Graylog não têm campo
  `type` nenhum e uma consulta positiva descartaria todo o histórico — que é
  exatamente a evidência que a âncora usa.
- **Um batimento a cada 5 min por gateway é ruído no índice**, para sempre.
  Doze mensagens por hora contra um stream que recebe uma linha por chamada
  de analista. Aceito: é o preço de poder alertar por ausência.
- **Os contadores morrem no restart.** Deliberado — ver item 3.
- **`head` vazio num gateway quieto.** Um processo que subiu e não atendeu
  ninguém não tem cabeça própria para relatar, e o batimento diz isso em vez
  de mentir um valor. A âncora deriva a cabeça das próprias linhas da
  cadeia, como sempre fez; o `head` do batimento é conferência, não fonte.

**Trade-offs assumidos:** trocamos a pureza de "uma forma de linha por
arquivo" pela única propriedade que faz o alerta significar alguma coisa —
batimento e auditoria atravessando exatamente o mesmo caminho. A Opção B
mantinha a pureza e entregava um alerta que fica verde durante a falha.

## Compliance

- [x] Automatizável? Sim.
- Onde vivem os testes:
  - `internal/audit/jsonl/jsonl_test.go`:
    `TestEmittedLineCarriesExactlyTheDeclaredSchema` (atualizado para o
    campo `type`), `TestHeartbeatCarriesExactlyTheDeclaredSchema`,
    `TestHeartbeatCarriesTheHeadItEmitted`,
    `TestHeartbeatOnAQuietGatewayReportsNoHead`,
    `TestHeartbeatSinkFailureIsReturnedNotSwallowed`,
    `TestHeartbeatDoesNotDisturbTheChain`.
  - `internal/audit/jsonl/leak_test.go`:
    `TestHeartbeatCarriesNothingAboutAnalystsOrCalls` — a mesma prova
    estrutural que as linhas de auditoria já têm, porque um campo novo num
    tipo novo não é coberto pelos testes do tipo antigo.
  - `internal/gateway/reconcile_test.go`:
    `TestStatus_CountsWhatTheTrailRecords` — conferido contra as linhas da
    trilha, e nao contra numeros escritos a mao, para que contar sem
    gravar (ou gravar sem contar) falhe — e `TestStatus_ReportsSuspension`.
  - `cmd/mcp-gateway/serve_test.go`:
    `TestServeStack_HeartbeatIsEmittedOnEveryRound`.
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 15 set 2026. Fecha o último item de
  "Security controls not yet designed" do `AGENTS.md` §2 e o alerta que o
  `WORKFLOW.md` listava como manual desde 11 set 2026.
- Não fecha injeção via resultado (ADR-0014) nem dá reconexão a credencial
  rotacionada (GAB-20). Nenhum dos dois é telemetria.
