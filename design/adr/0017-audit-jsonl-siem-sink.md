# 0017. Emitir a trilha de auditoria em JSONL para o SIEM, e fechar a âncora que a 0015 deixou aberta

**Status:** Accepted

## Contexto

A `0015` encadeou os registros por hash e foi explícita sobre o limite:
truncar a cauda deixa uma cadeia mais curta que verifica perfeitamente, e
detectar isso exige saber qual *deveria* ser a cabeça — informação que tem
de viver onde o gateway não escreve. O `-expect-head` foi construído como
gancho, e **onde a âncora externa mora ficou em aberto**.

*(Nota de 11 set 2026: a correção na `0015` amplia o que esta ADR fecha.
A cadeia é SHA-256 sem chave guardada na própria tabela, então uma edição
no meio seguida de re-encadeamento também verifica limpo — e também só
aparece na cabeça. A âncora construída aqui não é a solução do caso da
cauda: é a única detecção que existe contra quem escreve o arquivo do
banco.)*

Agora existe um Graylog. Ele responde a pergunta: a cabeça vive lá, porque
o gateway escreve num arquivo local que um shipper lê, e o gateway não tem
credencial nem caminho para reescrever o que o Graylog já indexou.

Vale ser preciso sobre o que isso vale, porque é fácil superestimar. O
Graylog não é um cofre: quem compromete o Graylog edita o que está lá. O
que muda é que **passam a ser dois sistemas diferentes, com contas
diferentes, e a discordância entre eles é visível**. É a mesma forma de
argumento da `0010` — uma âncora guardada ao lado daquilo que ela autentica
não é âncora — aplicada à cauda em vez de à assinatura.

Existe ainda uma razão operacional independente: hoje a trilha só é legível
por `mcp-gateway audit` numa jail FreeBSD, via SSH. O SOC já vive dentro do
Graylog. Uma trilha que ninguém abre não é evidência que ninguém use.

## Decisão

Um **segundo sink** para o mesmo `audit.Record`, em JSONL, num arquivo
local.

### 1. Segundo sink, nunca um segundo fluxo

`internal/audit/jsonl.Recorder` decora um `audit.ChainedRecorder` — na
prática o adaptador SQLite. Toda escrita vai para o SQLite **primeiro** e
só é emitida depois que aquela escrita comitou.

Existe **um** `audit.Record` e **uma** serialização dele, então o SIEM e a
trilha local não podem discordar sobre o que um registro *diz*. A única
divergência possível é de *presença*, e a ordem a torna unidirecional: nada
chega ao SIEM que já não esteja durável localmente.

Isso é o que dá sentido à detecção. Uma linha no Graylog sem linha
correspondente no SQLite é evidência de que a linha local sumiu. O
contrário — linha local sem linha no Graylog — é rotina: o shipper está
atrasado, ou caiu. As duas assimetrias precisam ser diferentes, e é a ordem
que as diferencia.

A alternativa descartada era montar um evento próprio para o SIEM, com os
campos "que fazem sentido num SIEM". Ela produz duas descrições do mesmo
fato que divergem no primeiro campo que alguém acrescenta de um lado só, e
aí a comparação entre as duas pontas deixa de significar qualquer coisa.

### 2. A falha do sink **não** estende a regra de recusa do `Dispatch`

O `gateway.Dispatch` recusa qualquer chamada que não consiga auditar antes
de despachar. Essa regra cobre a escrita **durável** e **para aí**.

Falha do sink — disco cheio, permissão mudada, arquivo rotacionado — é
registrada em `slog` no nível ERROR e engolida: `Record` devolve `nil`, a
chamada segue, a analista é atendida.

Estender a recusa até aqui converteria uma **falha de disponibilidade em
negação**. Um SOC que não consegue consultar o backend de casos porque um
arquivo de log ficou sem espaço é um SOC que este gateway quebrou, durante
um incidente, por causa de um log. O preço aceito é o inverso, e é menor:
sob falha do sink a trilha local continua completa e a cópia do SIEM fica
para trás — exatamente a divergência que o item 1 torna legível.

É também por isso que o sink é um **arquivo local** e nunca um cliente de
rede. O envio é problema de um processo separado (filebeat, vector, o que a
implantação já rodar). O caminho de request do gateway não pode ter
dependência remota nenhuma, nem engolida: um `connect` TCP pendurado é
latência, e latência nenhum `err != nil` esconde.

### 3. A linha carrega `prev_hash` e `hash` — e é essa a âncora da `0015`

Com os dois na linha, a cauda truncada localmente aparece como: a cabeça
que o `audit -verify` reporta não é a cabeça mais nova que o Graylog viu. E
o `-expect-head HASH` passa a poder tirar o valor esperado de uma consulta
ao SIEM em vez do caderno de alguém.

**A restrição que isso impôs.** O hash é calculado *dentro* do adaptador
SQLite, na mesma transação `BEGIN IMMEDIATE` que lê a cabeça e insere
(`0015` item 3), e `audit.Record` não tem campo de hash — `Recorder.Record`
devolve só `error`. Recalcular o hash fora da transação exigiria reler a
cabeça, o que corre com o próximo escritor.

Então: uma **segunda porta estreita**, `audit.ChainedRecorder`, que embute
`Recorder` e acrescenta `RecordChained(ctx, Record) (ChainLink, error)`. O
`Recorder` **não** é alargado: seu único chamador que importa precisa saber
se a escrita aconteceu, não em que ela hasheou, e alargá-lo empurraria um
retorno que ninguém lê para toda implementação.

`ChainLink` é `{Prev, Hash}`, e não só o hash: o esquema exige `prev_hash`,
e ele não é derivável do hash nem reconstruível fora da transação sem a
mesma corrida. Em erro, `ChainLink` é o valor zero — documentado na porta,
porque um `Prev` vazio é indistinguível de `GenesisHash` e um chamador que
ignorasse o erro leria uma escrita falha como "primeiro registro da
cadeia".

### 4. Esquema v1

Uma linha por registro, todos os campos sempre presentes (nenhum
`omitempty`: chave ausente e valor vazio são coisas diferentes para um
pipeline de log):

| campo | tipo | origem |
|---|---|---|
| `v` | int | versão do esquema, hoje `1` |
| `ts` | string | `Timestamp`, RFC3339Nano, normalizado para UTC |
| `chain` | string | qual cadeia/gateway esta linha pertence |
| `caller` | string | `AnalystIdentity` (o `sub` do IdP) |
| `backend` | string | `TargetUpstream` |
| `tool` | string | `Tool`, com namespace |
| `verdict` | string | `Outcome`: `allowed`, `denied` ou `failed` |
| `rule` | string | `Reason`, do conjunto fechado do gateway |
| `src` | string | `SourceAddress` |
| `prev_hash` | string | hash do registro anterior, hex, vazio no primeiro |
| `hash` | string | hash deste registro, hex |

`chain` existe porque dois gateways enviando para um mesmo stream produzem
hashes intercalados sem nada que diga a que trilha uma cabeça pertence, e
`-expect-head` contra a cabeça da cadeia errada é alarme falso em hora
ruim.

**`verdict` tem três valores, e uma chamada que falha emite DUAS linhas.**
É a consequência da `0012`: a falha acrescenta uma linha em vez de corrigir
a `allowed` que já está no disco. Quem contar linhas para responder
"quantas chamadas houve" conta a mais, por exatamente o número de falhas.
Conte linhas `allowed`; leia uma `failed` como anotação sobre a anterior.
Está escrito no tipo, no doc do pacote, e aqui, porque um painel de Graylog
é justamente onde alguém conta linhas sem ler documentação.

### 5. O que nunca pode aparecer numa linha, e por que é estrutural

Nunca: o token bearer, inteiro ou truncado; valores de credencial
resolvidos pelo vault; **argumentos e resultados de ferramenta** (carregam
indicadores e PII, e são a razão de este gateway existir em vez de quatro
notebooks com cópias das chaves de produção); texto de erro do upstream
(controlado pelo backend); claims de grupo do IdP.

Isso **não** é garantido por revisão de código. `Line` tem um conjunto fixo
de campos tipados, `Recorder.line` é seu único construtor, e as entradas
desse construtor são um `audit.Record` e um `audit.ChainLink` — sem `map`,
sem `any`, sem parâmetro de `error`, sem variádico. O `audit.Record` já não
carrega nenhum dos valores proibidos (`access.Identity` não tem campo de
token, e um teste de reflexão em `internal/access` quebra o build se alguém
acrescentar um). Vazar qualquer um deles por aqui exige editar `Line` — o
que é um erro de compilação a um passo de todo call site, e um diff que
ninguém deixa passar.

### 6. O que esta ADR **não** entrega, dito de frente

**A linha não é auto-verificável.** `ts` é o timestamp normalizado para
UTC, para conveniência do SIEM, enquanto a cadeia hasheia o timestamp no
offset que o relógio do gateway produziu. Quando esse relógio dá UTC as
duas formas coincidem byte a byte; quando não dá, são o mesmo instante
escrito diferente — e aí recalcular o hash a partir da linha dá outro
valor. Comparar hashes entre as duas pontas funciona; percorrer os elos
`prev`/`hash` dentro da própria cópia do SIEM funciona; **recalcular um
hash a partir de uma linha não é operação suportada**, e verificar conteúdo
contra hash continua sendo no lugar onde o registro está armazenado.

**Não existe campo `roles`.** O desenho original previa um, e ele não
sobreviveu ao código: `audit.Record` não tem papéis. As duas formas de
colocá-lo lá são ruins. Se o campo entrasse no `Canonical` da `0015`, toda
cadeia já gravada deixaria de verificar — é troca de tag de domínio, uma
emenda à `0015`, não um detalhe desta. Se ficasse **fora** do `Canonical`,
a linha passaria a carregar um campo que o hash não cobre, numa linha cujo
propósito inteiro é ser a âncora do hash: quem escreve o banco poderia
mentir nele sem quebrar verificação nenhuma. É exatamente a forma de
defeito que este projeto existe para não cometer.

Some-se que o decorador implementa `audit.Recorder` e recebe
`(ctx, Record)` — papéis não chegam até ele nem haveria de onde. Um campo
sempre vazio é decoração.

Fica assim: **`roles` não está no v1**. Quem precisar de papéis no Graylog
junta `caller` com o mapeamento grupo→papel do `config.toml`, que é onde os
papéis são escritos de qualquer forma. Acrescentá-lo de verdade é bump de
`v`, campo em `audit.Record`, emenda à `0015` e mudança no `gateway.record`
— nesta ordem, e com a migração da cadeia decidida antes da primeira linha
de código.

## Consequências

**Impactos positivos:** a pergunta em aberto da `0015` tem resposta, e o
`-expect-head` deixa de ser um gancho sem nada pendurado. A trilha passa a
ser legível onde o SOC já trabalha. E o custo por chamada é uma
serialização JSON e um `write` em `O_APPEND`, no mesmo caminho que já fazia
um `INSERT` transacionado.

**Impactos negativos aceitos:** mais um artefato no disco da jail, que
cresce e precisa de rotação — e a rotação é segura justamente por causa do
`O_APPEND`, mas é mais uma coisa para a implantação acertar. A cópia do
SIEM pode ficar para trás sem que o gateway seja impedido de nada, o que é
a escolha do item 2 e não um efeito colateral. E a detecção de truncamento
só existe **quando o sink está ligado e o shipper está rodando**: um
gateway montado sem o decorador continua com a cauda aberta exatamente como
antes. A `ChainedRecorder` é a costura, não a garantia, e o doc do pacote
`audit` diz isso com essas palavras.

### Integração, 11 set 2026 — como o sink é ligado

A seção é `[audit.siem]`, com duas chaves, e **as duas andam juntas**:

```toml
[audit.siem]
path  = "/var/log/mcp-gateway/audit.jsonl"   # ligar o sink é setar isto
chain = "gatte-jail-01"
```

`path` sem `chain` é recusado no carregamento porque `jsonl.New` exige o
nome da cadeia: sem a regra aqui, o arquivo carregaria, todo subcomando de
operador funcionaria, e o `serve` morreria no próximo restart com erro de
um pacote que o operador nunca configurou — GAB-30 pela sexta vez.

`chain` sem `path` é recusado por outra razão, e não por simetria: esse
bloco **se lê** como "esta trilha vai para o SIEM sob este nome" e não
manda nada. Defaultar um caminho seria pior ainda — passaria a escrever
registros atribuídos a analistas num arquivo que ninguém escolheu.

Espaço nas pontas de qualquer uma das duas também é recusado: os dois
valores são casados literalmente do outro lado (o glob do shipper, a
consulta `chain:"..."` no Graylog), então um valor com espaço é um valor
que nunca é encontrado.

No `cmd/mcp-gateway`, `auditRecorder` devolve a **porta** `audit.Recorder`
— nunca o tipo do adaptador — e sem o bloco devolve o recorder SQLite sem
decoração, exatamente como antes. `OpenFile` falhando é **fatal no
arranque**, e essa assimetria com a falha de `Emit` (engolida, item 2) é
deliberada: no arranque existe um operador que pediu o sink e pode agir
sobre o erro; às 03h não existe. O acessório do console
(`opEnv.auditTrail`) fica **sem** decoração de propósito: ele só lê.

**O que continua em aberto:** ninguém compara as duas cabeças
automaticamente. O `-expect-head` aceita um valor; quem o busca no Graylog
e com que frequência é procedimento de implantação, e enquanto for manual a
detecção depende de alguém olhar. Também não há alerta no Graylog para
"parou de chegar linha deste `chain`", que é como um shipper morto (ou
morto de propósito) se pareceria.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo:
  - um teste que grava N registros, apaga as últimas linhas do SQLite pelo
    SQL direto, exige que a cadeia **continue** íntegra (`0015` item 6) e
    que a única coisa que denuncie o corte seja a cabeça armazenada
    divergir da última `hash` emitida — é o teste que prova que a âncora
    funciona, e não só que existe;
  - um teste de vazamento modelado no
    `internal/vault/sopsage/leak_test.go`: despacho real por um `Gateway`
    real, com o segredo plantado em três lugares ao mesmo tempo (valor
    resolvido pelo vault, argumentos da ferramenta, texto de erro do
    upstream), exigindo que ele não apareça em lugar nenhum do arquivo
    emitido — com controle positivo, porque "não achei" contra um arquivo
    vazio é a resposta confiante e errada;
  - a variante JWT do mesmo, afirmando a ausência do token inteiro **e de
    cada um dos três segmentos** separadamente: token truncado ainda é
    credencial (`0012`);
  - um teste estrutural que desserializa cada linha para
    `map[string]any` e exige o conjunto de chaves **exatamente** igual ao
    esquema declarado, nas duas direções — para que um campo futuro
    carregando texto de erro quebre o build em vez de embarcar;
  - um teste que força falha do sink e exige que `Record` devolva `nil`,
    que a linha durável exista, e que o ERROR apareça no log.
- Onde vive: `internal/audit/jsonl/jsonl_test.go`,
  `internal/audit/jsonl/leak_test.go`.

## Notas

- Autor: Claude, 11 set 2026.
- Depende de `0012` (os três valores de `verdict` e o custo de duas linhas),
  de `0015` (a cadeia, e o item 6 que esta fecha) e ecoa `0010` pela mesma
  razão: uma âncora guardada ao lado daquilo que ela autentica não é
  âncora.
- Numeração: `0016` e `0017` estavam livres; esta tomou a **maior** das
  duas por combinação prévia, porque outra ADR estava sendo escrita em
  paralelo.
