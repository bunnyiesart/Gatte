# 0012. Completude do Audit Trail: falha, autenticação e endereço de origem

**Status:** Accepted

## Contexto

A revisão de 09 set 2026 encontrou três buracos no Audit Trail (GAB-24).
Eles importam mais que buracos equivalentes em outro lugar porque
`design/01-discovery.md` põe **Auditabilidade como prioridade #2** — é a
razão de isto ser um gateway de SOC e não um proxy — e porque o
`CONCEPTS.md` §2.5, pesquisa deste próprio projeto, diz que sem os campos
certos juntos "o log é decoração, não evidência".

1. **`OutcomeFailed` não é escrito por caminho nenhum**, e a CLI anuncia o
   filtro `audit -outcome failed`, que só pode voltar vazio. Uma chamada
   que estourou timeout fica registrada como `allowed`, indistinguível de
   uma que devolveu dados.
2. **Falha de autenticação não é auditada.** Força bruta de token, replay
   de token expirado e sondagem de audiência errada — o ataque que o
   RFC 8707 existe para barrar e do qual este projeto mais se orgulha —
   produzem zero registros.
3. **Não existe endereço de origem.** Um token roubado usado da máquina do
   atacante gera um registro byte a byte idêntico ao da analista legítima.

## Decisão

### 1. Falha vira um **segundo** registro, não uma correção do primeiro

O registro atual é escrito **antes** da chamada, de propósito: o comentário
em `endpoint.go` é explícito de que uma chamada não auditável é recusada,
porque sub-registrar é uma ação que ninguém vê. Isso não muda.

Então uma falha **acrescenta uma linha** com `OutcomeFailed`, em vez de
alterar a que já existe.

Alterar seria mais bonito de ler — uma linha por chamada — e está errado
por dois motivos. Um registro de auditoria que pode ser reescrito depois
não é evidência, é estado; e o par `allowed em T` + `failed em T+n` carrega
*mais* informação que a linha corrigida carregaria: diz que a chamada foi
de fato despachada e quanto tempo levou até falhar.

**Custo que precisa estar escrito:** uma chamada que falha produz **duas**
linhas. Quem contar linhas para saber "quantas chamadas houve" contará
errado. Está documentado no tipo e na saída da CLI, e é o motivo de
`Outcome` nunca ter tido zero value utilizável.

### 2. Falha de autenticação é auditada, com identidade que não mente

Registro com `Outcome` `denied` e `AnalystIdentity` marcada como
não-autenticada — nunca vazia, e num formato que não pode ser confundido
com um `sub` real de IdP.

**O `Reason` fica genérico de propósito.** O `internal/access/oidc` colapsa
oito causas distintas de rejeição num único erro para não virar oráculo, e
isso é correto; a consequência é que o `httpapi` também não sabe qual foi.
Registrar "autenticação falhou" é o que dá para registrar com honestidade.
O valor aqui não é a causa — é que a tentativa existiu, quando, e de onde.

**O token nunca entra no registro**, nem truncado. Um token rejeitado ainda
é credencial de alguém.

Fica anotado o que isto abre: quem martelar tokens gera uma linha por
tentativa, e nada aqui limita taxa. É melhor que o silêncio de hoje, e é
uma pendência real, não um detalhe.

### 3. Endereço de origem: a entrada **mais à direita** do `X-Forwarded-For`

Este é o ponto onde é fácil escrever a vulnerabilidade em vez do controle.

O gateway só é alcançável pelo nginx co-locado (`0011`), e o nginx manda
`X-Forwarded-For` com `$proxy_add_x_forwarded_for`, que é
`"$http_x_forwarded_for, $remote_addr"` — ou seja, **ele acrescenta ao que
o cliente mandou**. Um cliente malicioso que envie
`X-Forwarded-For: 10.0.0.1` faz o header chegar como `10.0.0.1, <ip real>`.

Portanto **a entrada da esquerda é controlada pelo cliente e não vale
nada**, e é justamente a que quase toda implementação lê. A entrada
correta é a **última**: foi o nginx que a escreveu, a partir do peer TCP
que ele mesmo enxergou.

Sem `X-Forwarded-For`, usa-se `RemoteAddr`.

Isto depende de o nginx ser o único caminho — que é exatamente a
propriedade que o `0011` garante e que a jail VNET tornou mensurável. Vale
notar a dependência: se um dia o gateway for alcançável direto, este campo
passa a ser falsificável, e a correção é restaurar a garantia do `0011`,
não passar a confiar em outro header.

## Consequências

**Impactos positivos:** `audit -outcome failed` passa a poder devolver
algo; um ataque contra a porta deixa rastro; e "foi mesmo a Ana?" passa a
ser respondível pelo trail em vez de por correlação de horário com o log do
nginx — que é o paliativo que está lá hoje, e que é pior justamente porque
exige juntar duas fontes.

**Impactos negativos aceitos:** duas linhas por chamada falha; volume maior
de escrita sob ataque, sem limite de taxa; e mais um campo no esquema, com
a migração `ALTER TABLE` tolerante a coluna duplicada que o retrofit de
`outcome`/`reason` já estabeleceu como padrão nesta tabela.

**O que continua em aberto:** a tabela é SQLite comum, sem append-only nem
encadeamento de hash, então quem tem escrita no banco ainda apaga ou edita
história. Fora do escopo aqui e registrado de propósito — a decisão do
`0010` sobre âncora de confiança tratou o mesmo ator para assinatura, e o
trail merece a mesma conversa um dia.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: um teste por buraco, cada um escrito primeiro contra o código
  atual, onde passa o comportamento errado. Para o item 3, especificamente
  um teste com `X-Forwarded-For` **forjado pelo cliente**, exigindo que o
  registro guarde o endereço que o proxy anexou e não o que o cliente
  inventou — sem esse teste a implementação "óbvia" (ler a primeira
  entrada) passaria despercebida.
- Onde vive: `internal/gateway/gateway_test.go`,
  `internal/gateway/httpapi/httpapi_test.go`,
  `internal/audit/sqlite/sqlite_test.go`.

## Notas

- Autor: Claude, 09 set 2026, a partir do GAB-24.
- Depende de `0003` (o Audit Trail existir), `0011` (o nginx ser o único
  caminho, do que o item 3 depende) e do precedente de migração aditiva
  que `outcome`/`reason` deixaram em `internal/audit/sqlite`.
