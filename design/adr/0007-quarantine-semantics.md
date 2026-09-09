# 0007. Semântica da quarentena: `changed` é permanente, bytes crus, um só predicado

**Status:** Accepted

## Contexto

`design/adr/0003-security-controls.md` decidiu **o mecanismo**: quarentena
por ferramenta, hash SHA-256 sobre nome + descrição + schema, três estados
(`pending`/`approved`/`changed`), padrão mcpproxy-go. A Fase 3 implementou
isso e, ao implementar, três perguntas de comportamento apareceram que o
`0003` não responde.

As três têm a mesma característica: a resposta "óbvia" é a insegura, e
alguém que leia só o código daqui a seis meses pode "consertar" as três
sem perceber que são deliberadas. Por isso viram ADR em vez de comentário.

## Decisão

### 1. `changed` é permanente até aprovação humana — não se auto-cura

Uma ferramenta que saiu de `approved` para `changed` **continua
`changed`** mesmo que a definição volte byte a byte ao baseline aprovado.
Só um `Approve` humano limpa o estado.

O comportamento "óbvio" seria voltar sozinha para `approved` quando o
hash volta a bater — parece correto e é exatamente o buraco. Um atacante
com acesso ao upstream troca a descrição por uma envenenada, espera a
janela de descoberta, e reverte. Com auto-cura, o estado final é
`approved`, idêntico ao inicial, e **nada no sistema registra que houve
uma janela** em que a ferramenta serviu uma definição envenenada. Com
`changed` grudento, a janela deixa marca e um humano precisa olhar.

O custo é real e aceito: um reformat inocente de descrição obriga uma
reaprovação. Preferimos esse atrito a um estado que se limpa sozinho.

### 2. O schema é hasheado como bytes crus, sem canonicalização JSON

Nada de normalizar o JSON antes de hashear. Dois bytes diferentes são
duas definições diferentes, ponto.

Canonicalizar significaria colocar um parser decidindo que duas
sequências de bytes "querem dizer a mesma coisa" **antes de um humano
olhar** — e diferenças de parsing são precisamente onde se escondem
ataques de confusão de parser. Um reformat de whitespace custa um clique
de aprovação; um parser generoso custa a garantia inteira.

Fail-closed no eixo certo: aqui o falso positivo é barato, o falso
negativo é o ataque.

> **CORREÇÃO, 08 Sep 2026 — esta garantia não é entregue hoje.**
>
> Descoberto ao implementar `internal/gateway/stdio` (Fase 5): o SDK
> oficial de MCP **decodifica `Tool.InputSchema` para `map[string]any`
> antes que qualquer código nosso o veja**. A própria documentação do SDK
> diz: *"From the client, this field will hold the default JSON marshaling
> of the server's input schema (a `map[string]any`)."* Os bytes literais
> do upstream já não existem na nossa fronteira.
>
> Ou seja: **há canonicalização, ela só não é nossa.** O que o hash cobre
> hoje é o re-marshal de um mapa Go, não o que o upstream escreveu.
>
> O que se perde, do mais brando ao mais sério:
> - Ordem de chaves e whitespace somem. Um reformat cosmético **não**
>   move o hash e **não** vira `changed`. Isso, isolado, seria aceitável.
> - Números normalizam: `1`, `1.0` e `1e0` viram o mesmo `float64`.
> - **Chaves duplicadas colapsam.** `{"a":1,"a":2}` vira `{"a":2}` no
>   decoder do Go. Dois schemas que um *outro* parser — o do cliente, o do
>   modelo — poderia ler de formas diferentes passam a ter o mesmo hash.
>   Isso é exatamente a confusão de parser que esta seção existia para
>   evitar, reintroduzida por baixo.
>
> O que **continua funcionando**: qualquer mudança semântica — descrição
> alterada (o vetor principal de tool poisoning), campo novo, tipo
> trocado, campo removido — ainda move o hash e ainda dispara `changed`.
> A defesa contra rug-pull não está quebrada; está com uma borda a menos
> do que este ADR afirmava.
>
> **A decisão em si continua de pé** — não vamos *acrescentar*
> canonicalização nossa. O que muda é a honestidade do texto: a garantia
> é "nenhuma normalização nossa", não "bytes crus do upstream".
> Fechar a diferença exige ler `tools/list` direto do fio, sem passar
> pelo SDK. Rastreado como item próprio, não resolvido aqui.

### 3. Um único predicado (`Usable`) governa visibilidade e execução

`Tool.Usable()` é a única resposta para "esta ferramenta pode ser
listada?" **e** "esta ferramenta pode ser chamada?". Não existe
`Visible()` nem `Callable()` separados. `Status` continua exportado, mas
só para o `Operator Console` renderizar — nunca para decidir acesso.

Dois predicados podem divergir, e a divergência tem um lado
especialmente ruim: "chamável porém oculta" é um caminho de execução que
não aparece em lista nenhuma, que é exatamente o que uma ferramenta
envenenada quer ser. Com um predicado só, esse estado é
**irrepresentável**, não apenas desencorajado.

Corolário: `List` **não** filtra. Um operador não pode aprovar o que não
consegue ver, então `pending` e `changed` aparecem na listagem — a
listagem é para o humano, o `Usable()` é para o despacho. São perguntas
diferentes e é correto que tenham respostas diferentes.

## Consequências

**Impactos positivos:** nenhuma sequência de observações automáticas
devolve uma ferramenta ao estado utilizável sem um humano; nenhuma
diferença de bytes passa por "equivalente"; nenhum caminho de execução
existe fora do que a listagem mostra.

**Impactos negativos aceitos:** mais reaprovações manuais do que o
estritamente necessário (reformat, reordenação de campos no schema
upstream). Em uma equipe de ~7 pessoas com quatro upstreams, o volume é
pequeno; se algum dia não for, a resposta certa é melhorar a ergonomia do
`Approve` no `Operator Console`, **não** afrouxar nenhuma das três regras
acima.

**Trade-offs assumidos:** atrito operacional em troca de não ter estado
que se limpa sozinho — coerente com `01-discovery.md`, onde
extensibilidade já é explicitamente "mais lenta por design" em favor de
segurança.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: `TestPendingAndChangedAreUnreachableButStillListed` prova a
  regra 3 pelos três caminhos por onde um chamador obtém uma ferramenta
  (`Observe`, `Get`, `List`); a sequência completa de rug-pull, incluindo
  a reversão da definição, prova a regra 1; o caso de colisão deliberada
  (`"ab"+"c"` vs `"a"+"bc"`) prova que a codificação com prefixo de
  tamanho da regra 2 não é ambígua.
- Onde vive (precisado em 09 set 2026 — esta linha dizia só
  `internal/quarantine/*_test.go`, o que cobre um dos três e não os
  outros dois):
  - Regra 1 (não se auto-cura): `TestRugPullSequence` e
    `TestObserved_ChangedDoesNotRevertWhenHashReturnsToBaseline`, em
    `internal/quarantine/quarantine_test.go`; e a mesma sequência
    atravessando a persistência em `TestRugPullSequence_ThroughTheAdapter`,
    `internal/quarantine/sqlite/sqlite_test.go`.
  - Regra 2 (codificação com prefixo de tamanho): `TestHash_IsUnambiguous`,
    `internal/quarantine/quarantine_test.go` — é este que carrega o caso
    `"ab"+"c"` vs `"a"+"bc"`.
  - Regra 3 (um só predicado, pelos três caminhos):
    `TestPendingAndChangedAreUnreachableButStillListed`, em
    `internal/quarantine/sqlite/sqlite_test.go`. Vive no pacote do
    adaptador, um nível abaixo do que esta linha apontava, porque prova a
    regra *através* da persistência e não só na memória —
    `TestUsable_IsTheSingleGate` é a metade em memória.
- Quando roda: a cada `make test`.

## Notas

- Autor: Claude, 08 Sep 2026, Fase 3.
- Elabora `0003` (que decidiu o mecanismo); não o revisa.
- A tag de domínio do hash (`mcp-gateway/quarantine/tool-identity/v1`) é
  distinta da do `Definition Signer`, de propósito: um digest de
  quarentena nunca deve poder ser confundido com uma assinatura de
  entrada, nem vice-versa.
