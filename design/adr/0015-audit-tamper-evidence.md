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

**Não escrever em lugar nenhum que a trilha é à prova de adulteração.** Ela
é detectável a adulteração *no meio*, com a cauda em aberto, e é assim que
a documentação passa a falar dela.

## Consequências

**Impactos positivos:** editar ou apagar um registro no meio da trilha
passa a ser visível, e o custo por chamada é um SHA-256 sobre alguns
campos. A verificação é um comando, não um procedimento.

**Impactos negativos aceitos:** escrever um registro deixa de ser um INSERT
solto e passa a ser uma transação serializada — sob concorrência alta isso
é um ponto de serialização. Para o volume deste gateway (um SOC de sete
pessoas) não é uma troca difícil; num volume maior, seria.

E a cauda continua cortável. Está registrado como limite, não resolvido.

**O que continua aberto:** onde a âncora externa vive. O `-expect-head`
existe para que essa decisão seja sobre implantação, não sobre este código.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: um teste que grava N registros, edita uma linha no meio pelo
  SQL direto, e exige que a verificação aponte aquela posição; outro que
  apaga uma linha do meio e exige o mesmo; um que encadeia concorrentemente
  e exige cadeia íntegra; e um que confirma que truncar a cauda **passa** na
  verificação — para que a lacuna seja um teste e não uma nota de rodapé.
- Onde vive: `internal/audit/audit_test.go`,
  `internal/audit/sqlite/sqlite_test.go`.

## Notas

- Autor: Claude, 11 set 2026, fechando a GAB-36.
- Depende de `0012` (os campos que a cadeia cobre) e ecoa `0010` (uma
  âncora guardada ao lado daquilo que ela autentica não é âncora — a razão
  de o item 6 não ser fingido como resolvido).
