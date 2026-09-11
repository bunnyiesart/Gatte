# 0016. Concessões por backend no papel ("profiles"), e a revisão da proibição de coringa

**Status:** Accepted

## Contexto

A capacidade (c) do ADR fundador de um projeto de referência privado
(`catallaxy`, `docs/decisions/0036-build-our-own-mcp-gateway.md`) descreve
o que falta aqui:

> *"Um profile declara **quais backends** um chamador vê **e quais tools
> por backend** … Uma tool ausente do profile do chamador é invisível em
> `tools/list` **e** recusada em `tools/call`."*

E enquadra a economia de contexto como objetivo de primeira classe, não
como efeito colateral de permissão:

> *"Um agregador que mostra todas as tools de todos os backends para todo
> agente gasta a janela de contexto do modelo num menu que ele em sua
> maioria não pode usar, e aumenta a taxa de erro de tool errada."*

Hoje o `[[role]]` deste gateway tem uma lista plana de nomes namespaced.
Isso já entrega a metade da permissão — `Authorize` e `ListTools` usam a
mesma `Policy`, então uma tool fora do papel já é invisível e já é
recusada. O que falta é a forma: **compor o papel por backend**. Com ~65
tools em quatro backends, dar a um papel a leitura inteira do
`threatintel` hoje significa escrever 28 nomes à mão, revisá-los, e
revisitar o arquivo toda vez que o upstream ganha uma tool.

Três decisões de fronteira precisam ser registradas antes da decisão em si,
porque cada uma foi verificada e nenhuma é óbvia.

### 1. `profile` não substitui `role`

O `mcp-gate` liga **um** profile a **um** chamador, através de uma lista
estática `callers[]` no arquivo. Este projeto não pode fazer isso: o
`0008` recusa deliberadamente um registro de principais — o Gatte é um
Resource Server OAuth, o conjunto de chamadores é do IdP, e a identidade
chega por claim de grupo. `Policy.RolesFor` devolve **vários** papéis e os
une; um profile que substituísse o papel teria que escolher um deles.

Então o profile do 0036 aparece aqui como **o papel**, e o vocabulário
difere assim:

| 0036 (`mcp-gate`) | aqui | por quê |
|---|---|---|
| `profile` | `[[role]]` | um por caller lá, vários por caller aqui (união) |
| `callers[]` no arquivo | `group_to_role` + claim do IdP | `0008`: a lista de chamadores é do IdP |
| `profiles.X.backends.Y.tools` | `[role.grants].Y` | mesma estrutura, uma camada a menos |

### 2. A premissa da proibição de coringa morreu, e isso foi verificado

`internal/access/access.go` recusava coringa com um motivo escrito:
*"a wildcard is how a role silently gains a tool that was added to an
upstream."* Na época isso era verdade. Hoje não é, e a verificação é no
código, não na intenção:

- o ticker do `0013` chama `quarantine.Store.Observe`, cujo contrato diz
  *"Observe never approves anything and never widens the usable set"*;
- uma tool vista pela primeira vez entra por `NewTool`, que a cria
  `StatusPending` com `ApprovedHash` vazio;
- `ListTools` e `Dispatch` passam ambos por `Gateway.admit`, que exige
  `Tool.Usable()` — `StatusApproved` **e** hash observado igual ao
  aprovado;
- não existe aprovação em massa nem automática: `q.Approve` tem um único
  chamador em todo o repositório, `cmd/mcp-gateway/tool.go`, num subcomando
  que aceita exatamente dois argumentos (servidor e tool).

Ou seja: sob `["*"]`, uma tool que aparece amanhã no upstream **não** é
servida amanhã. Ela nasce `pending`, invisível e não chamável, até um
humano aprovar aquela definição.

### 3. O custo real do coringa, dito por inteiro

O coringa não é de graça, e o ADR seria desonesto se parasse no parágrafo
acima. **Ele colapsa dois atos humanos independentes em um.**

Hoje uma tool chega a um analista por dois caminhos que se cruzam:

- **(a)** um operador aprova aquela *definição* na quarentena;
- **(b)** alguém acrescenta o nome dela a um papel.

Sob `["*"]`, **(a) passa a ser o único ato**. E (a) e (b) não são o mesmo
julgamento: (a) é uma decisão sobre **integridade de definição**, válida
para a frota inteira — "esta descrição e este schema não foram
envenenados"; (b) é uma decisão sobre **quem pode chamar** — "o N1 pode
deletar caso?". Quem aprova em (a) está respondendo a primeira pergunta, e
sob coringa a resposta dele vira também a segunda, para todo papel que
tiver escrito `["*"]` naquele backend.

Esse é o custo. É menor do que "a role silently gains a tool", que é o que
o comentário antigo afirmava, mas é real e não some ao ser nomeado.

### 4. Backend inexistente não dá para validar no load

Upstreams vivem no registro SQLite por decisão do `0001`. `Config.Validate`
não tem handle de registro e **não deve adquirir um**: `opRun`, o caminho
de todo subcomando de operador, chama `loadConfig` — e portanto `Validate`
— **antes** de `openStore`, justamente para que um arquivo errado falhe sem
depender de o banco abrir. Então "esta grant nomeia um backend que ninguém registrou"
não é erro de carga aqui. É diagnóstico de arranque — ver Consequências.

## Decisão

### 1. Mantém-se `[[role]]`, com composição por backend acrescentada

```toml
[[role]]
name  = "n1-triage"
tools = ["casemgmt.list_cases"]     # a forma plana continua válida

  [role.grants]
  casemgmt    = ["get_case", "add_note"]
  threatintel = ["*"]
  # um backend omitido aqui não é concedido de forma alguma
```

A chave é o nome registrado do upstream; os valores são os ids de tool
**como o próprio backend os chama**, sem namespace — a chave acima já diz
de que backend são. As duas formas se **unem** dentro do papel, e a união
entre papéis do `RolesFor` continua exatamente como era.

**A forma plana não fica depreciada.** Ela é a forma certa para conceder
três tools de três backends diferentes, e todo arquivo existente continua
carregando sem edição. Isso é garantido por teste
(`TestFilesWithoutGrantsAreUnchanged`), não por intenção.

### 2. `["*"]` é permitido, com o custo do item 3 do Contexto registrado

Concede todas as tools que aquele backend anuncia, agora e depois.
Continua sujeito à quarentena, e a prova disso é
`TestWildcardGrantServesOnlyApprovedTools`, que constrói um gateway real
sobre um backend falso e exige que uma tool dentro da grant e fora da
aprovação seja invisível **e** recusada.

O coringa vale só dentro de `[role.grants]`. Em `tools = [...]` os mesmos
três caracteres continuam sendo um nome literal — e `tools =
["casemgmt.*"]` passa a ser **recusado** no load em vez de carregar como um
nome que não casa com nada. Era um no-op silencioso antes; com um coringa
de verdade três linhas abaixo no arquivo, virou uma armadilha.

### 3. O que `Validate` recusa, e por que cada regra é estrutural

Recusado no carregamento, com mensagem nomeando o problema: chave de
backend ou id de tool vazio; qualquer um dos dois com espaço nas bordas;
qualquer um dos dois contendo o separador de namespace; `"*"` como chave de
backend; `"*"` misturado com nomes na mesma lista; id de tool repetido; o
mesmo backend escrito duas vezes no mesmo papel.

Duas dessas merecem justificativa, porque não são higiene:

- **Separador na chave de backend.** `Role.Allows` resolve a grant achando
  qual backend um nome namespaced pertence, e `SplitNamespaced` corta no
  **primeiro** separador. Uma chave `casemgmt.sub` casaria com
  `casemgmt.sub.x` — que é a tool `sub.x` do backend `casemgmt`, não uma
  tool de `casemgmt.sub`. Sem esta regra a grant alcança um backend que o
  operador não nomeou. Com ela, no máximo uma chave pode casar com um dado
  nome, e ela casa exatamente onde a tabela de rotas casa.
- **O mesmo backend duas vezes.** O TOML proíbe chave duplicada e o
  BurntSushi aplica isso **no nível superior** — mas não dentro de uma
  tabela aninhada. Verificado direto contra a v1.5.0: em `[role.grants]` o
  decoder aceita a duplicata e guarda a **última**, em silêncio. A ordem
  `casemgmt = ["get_case"]` seguida de `casemgmt = ["*"]` carrega como
  `["*"]` — um arquivo que se lê como limite e não aplica nenhum. É
  exatamente a classe de defeito deste projeto, e por isso é recusado em
  vez de resolvido por uma regra que o operador teria que conhecer.

### 4. `AllowedTools` passa a filtrar uma lista em vez de produzir uma

`Policy.AllowedTools(id)` prometia *"every tool this identity may call"*.
Sob `["*"]` essa promessa é impossível: a resposta depende do que a frota
anuncia neste instante, e `internal/access` nunca soube o que é um
upstream. A assinatura vira `AllowedTools(id, advertised)`.

As duas formas de manter a assinatura antiga eram piores. Devolver só as
concessões nominais **sub-reporta**, e um filtro que sub-reporta esconde
uma tool que mesmo assim é chamável — o *invisible execution path* que o
comentário de `Tool.Usable` nomeia como o pior dos dois lados. Devolver
algo que finge enumerar um coringa é a afirmação sem lastro que este
projeto passa a vida recusando. A função não tinha chamador de produção —
`Gateway.ListTools` sempre usou `Authorize` nome a nome — então o custo da
troca foi só nos testes.

### 5. Onde cada regra vive

`access.ValidateRole` é dona de todas as regras estruturais da grant, e
`Config.Validate` a chama — é a lição do GAB-30, uma regra dita uma vez.
Isso exige que `internal/access` conheça o separador de namespace, e ele
não pode importar `internal/gateway` (a dependência corre ao contrário).
Então existe uma segunda declaração, `access.nameSeparator`, **não
exportada**, e `TestNameSeparatorMatchesGateway` — em `package access_test`,
que pode importar os dois — quebra a build no dia em que divergirem. Uma
regra dita duas vezes é uma regra que vai divergir; esta está presa.

## Consequências

- Um papel pode conceder um backend inteiro numa linha, e o menu que cada
  analista vê passa a ser a fatia dele — a economia de contexto do 0036
  vira propriedade aplicável e não só efeito colateral.
- **Aprovar uma definição na quarentena passa a ser, para os papéis que
  escreveram `["*"]`, o único ato humano entre a tool e o analista.** Quem
  aprova precisa saber disso. Está dito aqui, no doc de `Role.Grants` e no
  doc de `config.Role.Grants`; não está dito na saída de
  `mcp-gateway tool approve`, e isso é dívida nomeada.
- **Resíduo conhecido, ~~não fechado~~ — fechado em 11 set 2026, ver o
  bloco no fim desta ADR:** um coringa em `X` também alcança as tools de um
  upstream chamado `X.alguma-coisa`, porque `SplitNamespaced` corta no
  primeiro separador e os dois casos são indistinguíveis no nome. Isso não é
  novo — `mergeRoutes` já documenta a mesma ambiguidade. **A frase seguinte,
  como estava escrita, era falsa e é o defeito desta casa:** as regras do
  item 3 garantem que *uma chave de grant* não leia um nome de forma
  diferente do roteamento, e **só isso**; elas não dizem nada sobre o nome do
  *upstream*, que é a outra metade e estava sem dono. Com `threatintel` e
  `threatintel.staging` ambos registrados, a grant `threatintel = ["*"]` — sem
  separador nenhum, portanto válida pelo item 3 — alcançava
  `threatintel.staging.debug_exec`. O fecho é do registro, como esta ADR já
  dizia.
- **Fica em aberto para a etapa de integração**, porque `Config.Validate`
  não pode responder: uma grant que nomeia um backend não registrado.
  Ela carrega, é bem-formada, e concede nada. O lugar de dizer isso é o
  arranque do `serve`, que já tem registro e quarentena na mão e já imprime
  `role reach`. Esse cálculo, aliás, hoje conta `len(r.Tools)` e passou a
  sub-reportar todo papel que usa grants.
- `config.example.toml` afirma, em caixa alta, `NAO EXISTE CORINGA. NEM
  casemgmt.*, NEM *, NEM PREFIXO.` Isso agora é falso pela metade e
  **precisa ser corrigido**: continua verdade para `tools = [...]`, e é
  falso para `[role.grants]`. Um arquivo de exemplo que descreve um
  controle que o código não aplica é precisamente o defeito que este
  projeto persegue. Não foi editado nesta etapa por estar fora dos
  arquivos que ela possui.

### Integração, 11 set 2026 — os três itens acima estão fechados

Escrito aqui, e não como ADR nova, porque nada disto é decisão nova: é a
execução do que esta ADR deixou nomeado.

- **Grant para backend não registrado** é aviso no arranque do `serve`
  (`unregisteredGrants` + uma linha `Warn` que **nomeia cada par (papel,
  backend)**). Não é fatal, de propósito: escrever a grant antes de
  registrar o backend é a ordem normal do trabalho, e um gateway que se
  recusasse a subir por um upstream desregistrado seria indisponibilidade
  fabricada por um diagnóstico. É suprimido quando `reg.List` falhou, pela
  mesma razão que o aviso de papel morto é: sem entradas para comparar,
  toda grant pareceria inexistente. **"Não registrado" é decidido pelo
  próprio `access.Role.Allows`, não por igualdade de nome** (`grantReaches`)
  — correção de 11 set 2026, depois de a primeira versão comparar a chave
  com os nomes do registro por igualdade exata. `Allows` casa a chave como
  prefixo até o separador, então `threatintel = ["*"]` endereça toda tool
  de uma entrada registrada como `threatintel.staging`; a igualdade exata
  não achava nenhum `threatintel` e fazia o arranque afirmar, sobre um
  registro que tem uma entrada que aquela chave endereça, que não há
  upstream registrado para ela — duas linhas abaixo de um `role reach`
  calculado pelo próprio `Allows`, que contava aquelas tools como
  observadas. Uma grant nominal continua sendo aviso nesse caso, e isso
  não é exceção: um id nominal não pode conter o separador, então só o
  coringa atravessa.

  O resíduo que tornava isso alcançável foi fechado no mesmo dia em outro
  lugar — `registry.UpstreamServer.Validate` recusa nome com separador e
  `Gateway.Connect` reconfere o contrato nas linhas que o store devolve —
  de modo que uma entrada dessa forma não serve tool nenhuma. A leitura
  errada continua errada mesmo assim: **um diagnóstico não pode ter a
  própria frase sustentada por uma regra de outro pacote.** É por isso que
  a correção ficou, e não foi descartada como redundante.
- **`roleReach` deixou de sub-reportar.** `Granted` soma `tools` e os ids
  nominais das grants; `Observed` passa por `access.Role.Allows` — o mesmo
  predicado do portão, não uma segunda opinião. Uma grant `["*"]` **não
  vira número**: aparece na linha como `threatintel:*`, e um papel cujo
  único alcance é um coringa que não alcança nada entra no aviso de papel
  morto (antes ficava de fora por ter denominador zero).
- **`mcp-gateway tool approve` diz quais papéis a aprovação autoriza**, e
  imprime o custo do coringa quando algum dos papéis chega por `["*"]`. É
  a dívida nomeada nas Consequências acima, paga onde o operador está.
- **`config.example.toml` foi corrigido**: a caixa agora separa as duas
  metades (`tools` sem coringa, `[role.grants]` com), traz um bloco
  `[role.grants]` **vivo** — com ids nominais, validado por
  `TestShippedExampleLoads` — e o custo do `["*"]` por inteiro. O exemplo
  **não** embarca um `["*"]`, e isso é fixado por teste
  (`TestShippedExampleShipsNoWildcardGrant`): exemplo é onde padrão vira
  hábito. O mesmo parágrafo falso vivia em
  `deploy/gateway-jail/config.toml.template` e também foi corrigido.

### Resíduo do prefixo, 11 set 2026 — fechado pelo registro

Escrito aqui, e não como ADR nova, porque esta ADR já nomeou o resíduo e já
disse de quem era o fecho ("decisão do registro"). O que segue é a execução,
mais a correção de uma frase que afirmava um controle que o código não
aplicava.

**O que estava errado.** O doc de `access.Role.Allows` dizia que a proibição
de separador na chave de grant faz com que "uma chave só possa casar até o
primeiro separador, que é exatamente como a tabela de rotas resolve o mesmo
nome", e concluía que uma grant nunca alcança "um backend que o operador não
nomeou". As duas leituras não coincidiam. A autorização resolve o backend com
`CutPrefix(tool, backend+sep)`; o roteamento resolve por igualdade exata sobre
`Namespaced(nome registrado, tool)`. Com `threatintel` e `threatintel.staging`
registrados, `threatintel.staging.debug_exec` é, para o roteamento, a tool
`debug_exec` de `threatintel.staging`, e para a autorização a tool
`staging.debug_exec` de `threatintel` — que a grant `threatintel = ["*"]`
concede. Reproduzido ponta a ponta antes da correção: o papel listava e
despachava com sucesso uma tool de um backend que ele nunca nomeou.

**O fecho, e por que é a regra certa.** `registry.UpstreamServer.Validate`
passa a recusar um nome que contenha o separador. Não é o "recusar nome que é
prefixo de outro" que esta ADR imaginava, e a diferença importa: ser prefixo
não é o problema — `threatintel` é prefixo de `threatintelx` e nenhum nome
construído para `threatintelx` começa por `threatintel` mais o separador. O
que torna um prefixo ambíguo é exatamente o separador. A regra é, além disso,
estrutural por entrada — decidível olhando só para ela —, enquanto "prefixo de
outro" exigiria do registro uma pergunta sobre a frota inteira a cada
`Register`, e ainda assim dependeria da ordem de registro.

`Register` valida; `List` não. Então `Gateway.Connect` reaplica o contrato da
entrada em tudo que sai do store, e recusa a entrada que não o satisfaz — uma
linha escrita antes da regra, ou por qualquer coisa que não este binário,
chega ao roteador por `List`, sem passar por `Validate`. A recusa acontece
**antes** do dial, então o comando daquele upstream não chega a rodar, e o
operador é avisado no log e no erro de `Connect` em vez de o backend sumir em
silêncio.

`mergeRoutes` continua onde está. Ele resolve o caso da *colisão* (dois
candidatos para um nome), que é outro: no cenário acima não há colisão alguma
— `threatintel.lookup_ip` e `threatintel.staging.debug_exec` são nomes
distintos, nada é descartado, e o furo é de autorização. Um não substitui o
outro.

- **Testes, todos vistos falhando contra o código pré-correção:**
  `TestGrantDoesNotReachAnUpstreamItOnlyPrefixes`
  (`internal/config/grants_prefix_test.go`) — gateway vivo, config carregada
  por `config.Load`, `debug_exec` aprovado na quarentena *antes* de conectar,
  para que a única coisa entre o papel e a tool seja a grant;
  `TestUpstreamNameRejectsNamespaceSeparator` e
  `TestUpstreamNameAllowsAPrefixOfAnotherName` (`internal/registry/name_test.go`);
  `TestRegistryNameSeparatorMatchesGateway`
  (`internal/registry/name_external_test.go`), que prende a terceira
  declaração do separador à de `internal/gateway` como
  `TestNameSeparatorMatchesGateway` já prende a segunda.
- **Custo aceito:** um upstream com ponto no nome deixa de ser registrável, e
  um que já esteja gravado deixa de ser servido. Nenhum dos quatro backends
  desta frota tem ponto no nome, e um nome com ponto já era indefensável — o
  próprio `mergeRoutes` documentava a ambiguidade, e `mcp-gateway tool
  approve` já relatava papéis errados para ele.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo, em três camadas, cada teste visto falhando contra o código
  pré-correção por mutação:
  1. **Domínio** — uma grant nominal alcança só o que nomeia; `["*"]`
     alcança o backend inteiro e para na fronteira dele (`threatintel.`,
     `threatintelx.lookup_ip`); uma grant não vaza para um papel que não a
     tem; cada recusa estrutural; o mapa de grants é clonado nas duas
     direções.
  2. **Arquivo** — cada recusa como o operador a encontra, pelo `Load`;
     dois papéis podem conceder o mesmo backend (o falso positivo que a
     detecção de chave duplicada poderia ter); arquivos sem `[role.grants]`
     carregam e autorizam exatamente o que autorizavam.
  3. **Gateway vivo** — `["*"]` serve só o que foi aprovado e nada do que
     está `pending`; `ListTools` e `Dispatch` concordam sobre um universo
     que inclui nomes concedidos-mas-não-aprovados e quase-acertos.
- Onde vive: `internal/access/grants_test.go`,
  `internal/access/grants_external_test.go`,
  `internal/config/grants_test.go`,
  `internal/config/grants_integration_test.go`,
  `internal/config/grants_prefix_test.go`,
  `internal/registry/name_test.go`,
  `internal/registry/name_external_test.go`.

## Notas

- Autor: Claude, 11 set 2026, a partir da capacidade (c) do ADR 0036 de
  `catallaxy` e do `experiments/mcp-gate/DESIGN.md`.
- Revisa o `0003` só no ponto do coringa, e revisa-o com a razão declarada
  de que a premissa daquela proibição foi verificada morta no código do
  `0013`. Depende do `0007` e do `0013` (a quarentena é o que torna o
  coringa defensável) e do `0008` (é o motivo de o profile virar papel em
  vez de vínculo por chamador).
- Um defeito foi encontrado enquanto isto era escrito e está corrigido:
  `Config.Validate` chamava `access.ValidateRole` sem passar `Grants`, o
  que deixava toda regra do item 3 sendo aplicada só por `NewPolicy`, no
  arranque do `serve`, e por nada na frente de quem edita o arquivo. GAB-30
  pela quinta vez.
