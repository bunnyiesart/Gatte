# 0027. Limite de taxa na auditoria de falha de autenticação

**Status:** Accepted — 16 set 2026.

## Contexto

A ADR-0012 decidiu auditar a falha de autenticação e declarou a dívida com
todas as letras: *"quem martelar tokens gera uma linha por tentativa, e nada
aqui limita taxa"*. O que ela não nomeou — e o que uma medição de 16 set 2026
mostrou — é que essas linhas disputam o escritor que o `Dispatch` precisa.

Medido contra o adaptador SQLite real, com o mesmo `store.Open` do gateway
(`journal_mode=wal`, `busy_timeout=5000`), tomando como "analista" uma
escrita a cada 20 ms:

| carga | p50 | p95 |
|---|---|---|
| ocioso | 846 µs | 1,46 ms |
| 100 401/s | 1,03 ms | 5,08 ms |
| 1000 401/s | 1,56 ms | 19,6 ms |
| flood sem pacing, 16 goroutines | 55,6 ms | **1,34 s** |
| flood sem pacing, 64 goroutines | — | **SQLITE_BUSY** |

O último caso é o que muda a classe do problema. `Dispatch` recusa qualquer
chamada que não consiga auditar antes — deliberadamente, e a linha de log diz
*"refusing unauditable call"*. Então o estado final não é lentidão: é **a
chamada de uma analista autenticada sendo recusada por causa de um estranho
sem credencial nenhuma**. A ADR-0012 comprou a detecção com uma linha por
tentativa; o preço não declarado é que quem escreve essas linhas decide se o
`Dispatch` consegue escrever a dele.

Há uma segunda metade, também medida: `RecordAuthFailure` era o único dos
três caminhos de auditoria que passava o contexto da requisição cru para a
escrita. Sob flood, com o cliente desligando 10 ms depois de mandar, 9 de 50
registros de falha se perdiam — o flood suprimia a própria evidência. Isso
foi corrigido adotando o `auditWriteCtx` que os outros dois já usavam, e
**essa correção piora este problema**: a escrita deixa de ser abandonada e
passa a segurar a goroutine por até 5 s. As duas entram juntas, por isso.

## Alternativas

### Opção A — Recusar antes de auditar

| Prós | Contras |
|---|---|
| Elimina a contenção por completo | Devolve exatamente o que a ADR-0012 comprou: a rajada de 401 **é** a detecção de token grinding, e sem linha nenhuma o ataque volta a ser invisível |

### Opção B — Fila com escritor único e descarte

Medido, e é o resultado negativo que decide o desenho:

| cenário | analista p50 | p95 |
|---|---|---|
| sem flood | 777 µs | 1,29 ms |
| flood, mesmo arquivo | 55,6 ms | 1,34 s |
| **fila sem teto, 1 escritor** | 84 µs | **1,51 s** |
| teto global de 100/s | 1,79 ms | **2,06 ms** |

A fila sozinha não entrega nada. Ela tira a espera da goroutine que produz a
linha — e essa goroutine é a do atacante, que não estava esperando. O lock
continua saturado e a analista continua parada. Só um teto na taxa de dreno
resolve, e aí é um limitador de taxa com uma fila parafusada.

### Opção C — Arquivo separado para a trilha de autenticação

| Prós | Contras |
|---|---|
| Resolve (p95 271 µs) | Duas cadeias, duas cabeças, duas âncoras a comparar — exatamente o que o campo `chain` da ADR-0017 existe para não haver |

### Opção D — Balde de fichas antes da escrita (escolhida)

| Prós | Contras |
|---|---|
| Devolve ao ruído (p95 2,06 ms contra 1,29 ms ocioso) sem tocar na cadeia: continua um escritor, uma transação, ordem de inserção | A trilha deixa de responder "quantas tentativas" e passa a responder "esta origem tentou, e o teto disparou" |
| O sinal de ataque sobrevive, porque a primeira tentativa de cada origem sempre é auditada | Estado novo no processo, e estado chaveado por algo que o atacante escolhe |

## Decisão

**Opção D**, dentro de `gateway.RecordAuthFailure`, antes de `g.record`.

### 1. Onde mora, e por quê ali

No `Gateway`, não no `httpapi`. A ADR-0021 item 4 e o comentário de
`RecordRefusedProbe` dizem a mesma coisa: todo registro deste sistema é
escrito por um componente só, senão atribuição, ordem e razões divergem
entre superfícies. **A decisão de não escrever um é da mesma natureza** e
mora no mesmo lugar. Além disso `g.now()` já é injetável, então o limitador
tem teste determinístico em vez de `time.Sleep`.

### 2. O log nunca é limitado; a escrita é

`g.log.WarnContext` continua acontecendo em **toda** tentativa, com a origem.
Medido: `slog` em JSON para arquivo sustenta 370–458 mil linhas/s, vinte
vezes a capacidade do banco. A contagem exata sobrevive ali, dentro do
processo, de graça.

O que é limitado é a linha durável — a que custa uma transação.

### 3. Três desfechos, e o do meio é o que salva a detecção

- **admite** → escreve como hoje, com `reasonAuthFailed`.
- **marca** → escreve UMA linha por origem por janela, com uma razão nova,
  `auth failures rate-limited`. É o que diz ao operador que aquela origem
  passou do teto, e é o que impede a supressão de ser silenciosa.
- **descarta** → só o contador em memória.

**O marcador cobre os DOIS baldes.** Uma tentativa recusada pelo teto global
— e não pelo balde da origem — também gera marcador, senão um ataque
distribuído por muitas origens cai inteiro no descarte silencioso, que é o
buraco que a primeira versão deste desenho tinha.

### 4. O mapa de origens é limitado, e o estouro degrada para o teto global

Um limitador cujo estado o atacante faz crescer fecha um DoS abrindo outro.
Então: no máximo `maxSources` baldes vivos (1024); balde ocioso além da
janela é elegível a despejo; e **no estouro do mapa a tentativa cai no teto
global, nunca no silêncio**. A propriedade de segurança é o teto global, que
não depende do mapa.

### 5. Constantes no código, não chaves de configuração

`5/s` por origem com rajada de 20, `50/s` global com rajada de 200, janela de
marcador de 1 min. São números que saíram de uma medição para uma implantação
de sete analistas — não são preferência de operador, e transformá-los em
configuração é criar mais quatro coisas para alguém operar e errar. A
ADR-0009 pôs papel no arquivo porque papel é política; isto é mecânica.

Quem precisar mudar muda no código, com o diff revisado — que é a mesma
postura do `MinResultBytes`.

### 6. O que se perde, escrito com o nome que a ADR-0012 usou

Depois do teto, a trilha responde *"esta origem tentou"* e *"o teto disparou
para esta origem neste minuto"*. Ela **deixa de responder "quantas"**. Quem
quiser a contagem exata lê o log operacional, que não é limitado — e essa é
uma troca de onde o dado vive, não de existir ou não.

Duas consequências menores e reais:

- **`Status.Denied` vira subcontagem durante um ataque.** O contador da
  ADR-0021 é incrementado dentro de `record`, depois da escrita durável, e
  linhas suprimidas não são escritas — então o batimento fica *mais quieto*
  sob flood. Nada é acrescentado ao esquema do batimento para compensar:
  fazê-lo contradiria a ADR-0021 item 4 (*os contadores são as linhas
  escritas*) e forçaria `v` para 3, com o extrator do Graylog junto. O sinal
  de ataque é a razão nova na trilha, não um contador novo.
- **A supressão é distinguível por tempo.** Uma rejeição suprimida pula uma
  escrita e volta mensuravelmente mais rápido, então um chamador consegue
  inferir que passou do teto — inclusive o consumo do orçamento global por
  terceiros. Baixo, e não vale um atraso artificial num caminho de rejeição.

## Consequências

**Impactos positivos:** a recusa da chamada de uma analista autenticada por
causa de um estranho deixa de ser possível pelo caminho da trilha; o
`RecordAuthFailure` passa a preservar a própria evidência sem que isso vire
acúmulo de goroutines.

**Impactos negativos aceitos:** a trilha perde a contagem por tentativa; o
batimento fica mais quieto sob ataque; e há estado novo, limitado, chaveado
por um valor que o atacante escolhe.

## Compliance

- [x] Automatizável? Sim, e **não por benchmark**: o chicote de teste deste
  repositório abre o SQLite com `SetMaxOpenConns(1)` para `:memory:`, então
  não há disputa de lock para medir ali. Um teste de contenção seria teatro.
  O que se testa é o comportamento do limitador, com relógio injetado.
- Onde vivem os testes, em `internal/gateway/authlimit_test.go` e
  `internal/gateway/reconcile_test.go`:
  - `TestAuthLimit_FirstAttemptFromASourceIsAlwaysAudited`
  - `TestAuthLimit_MarksOncePerWindowThenDropsSilently`
  - `TestAuthLimit_GlobalCeilingAlsoMarks` (o buraco da primeira versão)
  - `TestAuthLimit_SourceMapIsBounded`
  - `TestRecordAuthFailure_UnderFloodStillAuditsAndStillMarks`
  - `reasonAuthFlood` nas duas listas de
    `TestAuditReasons_AreAStableWireContract`.
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 16 set 2026. A medição veio antes do desenho,
  e é ela que autoriza a escolha: a Opção B parecia a resposta óbvia e os
  números a recusaram.
