# 0015. Tornar a trilha de auditoria detectável a adulteração, e dizer até onde isso vai

**Status:** Accepted

## Contexto

`audit_records` é uma tabela SQLite comum. Sem restrição de append-only,
sem encadeamento, sem assinatura. Quem escreve o arquivo do banco edita uma
linha, apaga uma, ou remove um intervalo — e nada depois disso percebe.

É **o mesmo ator contra o qual a ADR-0010 existe.** Aquela ADR tirou a
âncora de confiança do banco justamente porque "pode escrever o registry" e
"pode escrever as assinaturas" eram uma permissão só, e verificar uma
entrada contra uma chave guardada ao lado dela não provava nada. A trilha
de auditoria tem exatamente o mesmo formato e nenhuma proteção equivalente.

Isso pesa mais aqui do que pesaria em outro lugar. Auditabilidade é a
prioridade **#2** deste projeto (`design/01-discovery.md`) — a razão
declarada de isto ser um gateway de SOC e não um proxy. E o `CONCEPTS.md`
§2.5, pesquisa do próprio projeto, é direto: um log que não tem o que
precisa é "decoração, não evidência". A GAB-24 fechou os buracos de
*conteúdo*; nada foi feito sobre a trilha ser **reescrita**.

Vale ser preciso sobre a ameaça, porque ela é mais estreita do que soa:
exige acesso de escrita ao sistema de arquivos da jail, o que já implica
comprometimento substancial. Não é ataque remoto. O que muda é quanto a
trilha vale **durante uma resposta a incidente** — que é exatamente quando
ela é lida, e exatamente quando o atacante tem motivo para editá-la.

## Decisão

Encadeamento por hash, com a cauda declarada em aberto.

> **CORREÇÃO, 11 set 2026 — a divisão "meio detectado, cauda em aberto"
> não existe, e a cadeia sozinha não cobre o ator nomeado no Contexto.**
>
> `prev_hash` e `hash` são colunas comuns da própria `audit_records`, o
> SHA-256 é **sem chave**, e `audit.ChainHash` é **exportado**. Quem
> escreve o arquivo do banco — literalmente o ator do Contexto, o mesmo da
> `0010` — edita a linha do meio e reescreve `(prev_hash, hash)` de todas
> as seguintes com uma dúzia de linhas de SQL e a função pública deste
> projeto. `VerifyChain` então responde **íntegra**. Vale igual para apagar
> uma linha do meio e para inserir uma forjada. Reproduzido, não deduzido:
> `TestVerifyChain_RechainedMiddleEditVerifiesClean` e
> `..._RechainedMiddleDeleteVerifiesClean` em
> `internal/audit/sqlite/rechain_test.go`, e
> `TestRunAuditVerify_RechainedEditNeedsTheAnchor` pela porta do operador.
>
> A ironia é a que o próprio Contexto anuncia: a `0010` tirou a âncora de
> dentro do banco porque *uma âncora guardada ao lado daquilo que ela
> autentica não é âncora*. Esta ADR guardou o hash ao lado do registro que
> ele autentica e escreveu que estava honrando a `0010`.
>
> **O que a cadeia entrega de fato:** detecção de adulteração que **não**
> re-encadeou — edição descuidada, escrita parcial, processo que não rodou
> este código. Não é nada, e continua valendo a pena pelo custo de um
> SHA-256 por chamada. Mas não é o ator do Contexto.
>
> **O que passa a ser tudo:** qualquer reescrita muda a **cabeça**, e esse
> é exatamente o mesmo e único sinal que o truncamento de cauda produz.
> Logo não há duas metades: há **uma** detecção — comparar a cabeça com um
> valor guardado onde este gateway não escreve (`-expect-head`, âncora da
> `0017`) — e, sem ela, nada é detectado contra esse ator. O item 6 abaixo
> segue correto no que diz; o que estava errado era tratá-lo como a
> *exceção* em vez do caso geral.
>
> **Por que não trocar por uma MAC com chave agora:** o gateway precisa da
> chave para escrever cada registro, então ela vive onde este processo a
> lê. Na jail, quem escreve o arquivo do banco em geral também lê o arquivo
> da chave, e o degrau que uma HMAC acrescenta ("escrita no banco" →
> "escrita no banco + leitura da chave do gateway") é real mas menor do que
> esta ADR afirmou ter entregue, e não dispensa a âncora externa. Se esse
> degrau for desejado, ele é **ADR nova** — esquema, migração da cadeia já
> gravada, configuração — e não emenda silenciosa aqui.
>
> Corrigidos nesta data, para dizer só o que o código entrega: o doc de
> pacote de `internal/audit`, `ChainCheck`/`ChainHash`/`ChainVerifier`, o
> texto de `mcp-gateway audit -verify` (ajuda e saída de sucesso),
> `deploy/freebsd-jail.md` e a checklist do `WORKFLOW.md`.

### 1. Cada registro carrega `prev_hash` e `hash`

`hash = SHA-256(canonical(registro) || prev_hash)`, guardados em hex.

`canonical` é TLV com prefixo de comprimento e uma tag de domínio própria
(`mcp-gateway/audit/chain/v1`), pelo mesmo motivo que o `signer` já tem a
dele: com concatenação ingênua, `tool="ab"` + `reason="c"` e `tool="a"` +
`reason="bc"` produzem os mesmos bytes, e aí dois registros diferentes têm
o mesmo hash. A tag impede que bytes canônicos produzidos aqui sirvam em
outro contexto que use o mesmo esquema.

O primeiro registro encadeia a partir de `prev_hash` vazio.

### 2. A ordem da cadeia é a ordem de **inserção**, não a do timestamp

`id`, não `timestamp`. O timestamp vem do chamador, empata com frequência
(o `Dispatch` escreve dois registros de um relógio só quando uma chamada
falha) e não é monotônico por construção. Encadear por ele daria uma
cadeia cuja ordem depende de um campo que o próprio registro declara — e
uma verificação que reordena para conferir não verifica nada.

`List` continua ordenando por timestamp, que é o que o operador quer ler.
São duas ordens diferentes de propósito, e a verificação usa a sua.

### 3. Ler a cabeça e inserir na mesma transação

Duas chamadas concorrentes que leem a mesma cabeça e inserem produzem um
ramo: dois registros apontando para o mesmo antecessor, e a verificação
acusa quebra num banco que ninguém adulterou. A inserção passa a ser
`BEGIN IMMEDIATE`, lê o último `hash` e grava, atomicamente.

### 4. A migração preenche o passado — e isso **não** autentica o passado

Bancos existentes têm linhas sem hash. A migração as encadeia em ordem de
`id` e grava, numa tabela de metadados, o maior `id` que existia naquele
momento.

O que esse preenchimento dá: uma cadeia única e contínua, e detecção de
qualquer edição **a partir dali**. O que ele não dá, e precisa estar escrito
porque a tentação de ler como se desse é grande: se alguém já tinha editado
uma linha antes da migração, o preenchimento assina a versão editada sem
reclamar. Registros anteriores à fronteira valem o que o banco valia no
instante da migração — nada mais.

Por isso a fronteira é **guardada e reportada**, em vez de esquecida. A
verificação diz quantos registros foram encadeados retroativamente, para
que ninguém leia "cadeia íntegra" como "estes registros são autênticos
desde que foram escritos".

### 5. `audit -verify` percorre a cadeia e reporta a primeira quebra

Sai a posição, o registro, o hash esperado e o encontrado. E a cabeça atual
sempre, íntegra ou não.

### 6. Truncamento da cauda **não** é detectado, e não é afirmado

Cortar os últimos N registros deixa uma cadeia perfeitamente válida, mais
curta. Nenhum encadeamento resolve isso sozinho: a propriedade que falta é
saber qual *deveria* ser a cabeça, e essa informação tem de viver onde o
gateway não alcança.

O que dá para fazer barato, e é o que fica feito: `audit -verify` imprime a
cabeça, e `-expect-head HASH` compara contra um valor que o operador
guardou fora. Onde esse valor é guardado é decisão de implantação, não de
código, e fica em aberto — mas o gancho existe, então a decisão pode ser
tomada depois sem mexer aqui.

**Não escrever em lugar nenhum que a trilha é à prova de adulteração.**
Nem, depois da correção de 11 set 2026 acima, que ela é "detectável a
adulteração no meio": ela detecta adulteração que não re-encadeou, e
qualquer adulteração — meio ou cauda — só aparece na comparação da cabeça
contra um valor externo. É assim que a documentação passa a falar dela.

## Consequências

**Impactos positivos:** adulteração que não recomputa os hashes seguintes
— edição descuidada, escrita parcial, processo que não roda este código —
passa a ser visível, e o custo por chamada é um SHA-256 sobre alguns
campos. A verificação é um comando, não um procedimento. E toda alteração,
inclusive a que re-encadeia, muda a cabeça, o que dá à âncora externa da
`0017` uma única grandeza para comparar. *(Este parágrafo dizia "editar ou
apagar um registro no meio da trilha passa a ser visível" — ver a correção
de 11 set 2026 na Decisão.)*

**Impactos negativos aceitos:** escrever um registro deixa de ser um INSERT
solto e passa a ser uma transação serializada — sob concorrência alta isso
é um ponto de serialização. Para o volume deste gateway (um SOC de sete
pessoas) não é uma troca difícil; num volume maior, seria.

E a cauda continua cortável — como, depois da correção de 11 set 2026,
continua reescritível qualquer ponto da trilha para quem re-encadeia.
Registrado como limite, não resolvido.

**O que continua aberto:** onde a âncora externa vive (a `0017` responde
para esta implantação) e se vale a pena o degrau de uma MAC com chave —
que, se for querido, é ADR nova. O `-expect-head` existe para que a
primeira decisão seja sobre implantação, não sobre este código.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: um teste que grava N registros, edita uma linha no meio pelo
  SQL direto, e exige que a verificação aponte aquela posição; outro que
  apaga uma linha do meio e exige o mesmo; um que encadeia concorrentemente
  e exige cadeia íntegra; e um que confirma que truncar a cauda **passa** na
  verificação — para que a lacuna seja um teste e não uma nota de rodapé.
- Da correção de 11 set 2026, pela mesma regra: dois testes que editam e
  apagam uma linha do meio, re-encadeiam para a frente com a
  `audit.ChainHash` **exportada**, e exigem que a verificação responda
  **íntegra** — cada um com o controle de que a mesma adulteração *sem*
  re-encadeamento é acusada, senão o teste não prova nada; e a exigência de
  que a cabeça mude, que é o que a âncora externa compara. Mais dois na
  saída do operador: a ajuda e o sucesso do `-verify` têm de nomear o
  re-encadeamento e não podem afirmar detecção no meio.
- Onde vive: `internal/audit/audit_test.go`,
  `internal/audit/sqlite/sqlite_test.go`,
  `internal/audit/sqlite/rechain_test.go`, `cmd/mcp-gateway/audit_test.go`.

## Notas

- Autor: Claude, 11 set 2026, fechando a GAB-36.
- Correção de 11 set 2026 (na Decisão) escrita no mesmo dia, por revisão:
  a ADR afirmava cobrir o ator do Contexto e não cobria. Comportamento não
  mudou; o que mudou foi a afirmação, até caber no que o código entrega.
- Depende de `0012` (os campos que a cadeia cobre) e ecoa `0010` (uma
  âncora guardada ao lado daquilo que ela autentica não é âncora — a razão
  de o item 6 não ser fingido como resolvido, e, pela correção, a razão de
  esta ADR ter repetido o próprio anti-padrão que citava).
