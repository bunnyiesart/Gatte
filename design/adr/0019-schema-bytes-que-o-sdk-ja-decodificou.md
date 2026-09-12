# 0019. Os bytes do schema já foram decodificados antes de chegarem aqui, e isso fica aceito em voz alta

**Status:** Accepted

## Contexto

A ADR-0007 §2 decidiu registrar o schema de uma tool como **bytes crus, sem
canonicalização de JSON**. O raciocínio era bom e continua sendo: canonicalizar
põe um parser decidindo que duas sequências de bytes "querem dizer a mesma
coisa" **antes** de um humano olhar — e é exatamente aí que vivem os ataques
de confusão de parser.

O problema é que essa decisão não é nossa para tomar nesta camada. O SDK
oficial de MCP decodifica `Tool.InputSchema` para `map[string]any` antes de
qualquer linha deste projeto rodar. Da documentação do próprio SDK:

> From the client, this field will hold the default JSON marshaling of the
> server's input schema (a `map[string]any`).

Então os bytes literais do upstream já não existem na nossa fronteira. **Há
canonicalização — ela só não é nossa.** O que o `Hash` cobre é o
re-marshal de um mapa Go.

### O que isso custa, medido e não descrito

Está em `TestRawJSON_TheSDKRoundTripCollapsesDuplicateKeys`:

- **Chaves duplicadas colapsam.** `{"x":1,"x":2}` vira `{"x":2}` no decoder
  de Go. Dois schemas que um parser *diferente* — o do cliente, o do modelo —
  poderia ler de formas diferentes passam a ter **uma** impressão digital. É
  precisamente a classe que a §2 existia para impedir, reintroduzida por
  baixo dela. A RFC 8259 deixa o comportamento de nomes duplicados
  indefinido, que é o motivo de a §2 querer os bytes.
- **Números normalizam.** `1`, `1.0` e `1e0` viram o mesmo `float64`.
- Ordem de chaves e espaços somem, então uma reformatação puramente
  cosmética não marca a tool como `changed`. Isso sozinho seria aceitável.

### O que continua funcionando, e o teste também fixa

Toda mudança **semântica** ainda move o hash: descrição alterada — o vetor
primário de tool poisoning —, campo novo, tipo trocado, campo removido. A
defesa contra rug pull não está quebrada. Ela tem uma aresta a menos do que a
ADR-0007 afirmou.

## Decisão

**Aceitar a lacuna, explicitamente, e parar de afirmar o contrário.**

### 1. A afirmação falsa sai de onde o leitor a encontra primeiro

`gateway.ToolDef.InputSchema` dizia *"raw JSON schema bytes, passed through
unaltered ... not reformatted or canonicalized anywhere in this system"*. O
`stdio.rawJSON` já dizia a verdade no ponto em que o fato acontece; o tipo
dizia o oposto no ponto em que alguém lê primeiro. Corrigido.

### 2. Não se constrói um parser de fio para fechar isso agora

Fechar exige ler o `tools/list` do fio em vez de através dos tipos do SDK.
Isso é factível e mais barato do que soa — o transport do SDK é envolvível
(o `lab/probe` já lê tráfego cru assim) e um `json.RawMessage` no campo do
schema preservaria os bytes literais enquanto o envelope é decodificado.

Não entra mesmo assim, por três motivos que valem mais escritos do que
descobertos:

- **Passa a haver duas fontes de verdade** para a mesma lista — a decodificada
  pelo SDK e a nossa. Elas podem discordar, e uma discordância silenciosa
  entre elas é pior do que a lacuna que fechariam.
- **O risco residual é estreito.** É um atacante que sirva um schema cuja
  representação em *bytes* difira do seu significado decodificado de um jeito
  que importe para o cliente e não para o Go. Estreito não é zero, e é por
  isso que isto é uma ADR e não uma nota.
- A ADR-0007 não fica corrigida em silêncio: ela afirmou uma propriedade que
  o código não entrega, e o registro disso é este documento.

### 3. O custo fica preso por teste, não por prosa

`TestRawJSON_TheSDKRoundTripCollapsesDuplicateKeys` exige que os dois schemas
colapsem e que o hash seja o mesmo — ou seja, **falha no dia em que alguém
fechar a lacuna**. Isso é de propósito. A mensagem dele manda substituir o
teste por um que exija o oposto, e não apagá-lo: um teste apagado é
indistinguível de um que nunca existiu.

O mesmo teste carrega o controle que impede a leitura errada: tipo de campo
alterado ainda move a digital. Sem esse controle, este documento leria como
"a impressão digital não serve", que é falso e muito pior.

## Consequências

**Impactos positivos:** a documentação passa a dizer o que o código faz, e o
custo exato está medido num teste em vez de descrito numa frase.

**Impactos negativos aceitos:** dois schemas byte-diferentes podem partilhar
uma aprovação. Um operador que aprovou um aprovou o outro, e não há nada na
interface que mostre isso — porque, nesta camada, não há diferença a mostrar.

**O que continua aberto:** a GAB-15. Esta ADR aceita a lacuna; não a fecha. E
o teto de tamanho de resposta da ADR-0014 é aplicado ao re-marshal e não aos
bytes do upstream — na mesma direção, e sem esconder payload, porque o
encoder de Go não emite espaço insignificante.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: o teste citado acima, que falha se a lacuna for fechada e cujo
  controle falha se a defesa contra rug pull quebrar.
- Onde vive: `internal/gateway/stdio/stdio_test.go`.

## Notas

- Autor: Claude, 12 set 2026, fechando a metade da GAB-15 que é fechável sem
  reescrever o diálogo com os upstreams.
- Corrige o enunciado da `0007` §2. Depende da `0014` pelo mesmo re-marshal.
