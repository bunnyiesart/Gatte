# 0018. O cofre continua plano, e o compartilhamento passa a ser dito em voz alta

**Status:** Accepted

## Contexto

O cofre é um mapa plano com chave no **nome da variável de ambiente**, sem
dimensão de upstream. Uma credencial é identificada por *como a variável se
chama*, não por *qual backend a recebe*.

A consequência está na GAB-32: dois backends que ambos querem `API_TOKEN`
não conseguem ter valores diferentes. Um recebe silenciosamente a
credencial do outro. Não há erro, não há aviso, e o `upstream list` não
mostra nada — a entrada está correta, porque está mesmo: a colisão é no
namespace do cofre, não no do registry.

Vale separar o que já está certo, porque é fácil ler isto como um vazamento
e não é. O **isolamento** entre upstreams é real e verificado: o
`resolveEnv` monta o ambiente do filho do zero, a partir dos nomes
declarados por exatamente uma entrada, então nenhum upstream enxerga as
variáveis de outro. A lacuna é de **nomenclatura**, e o dano dela vive
inteiro no que o operador acredita.

Hoje a frota não sofre: os quatro nomes por backend são distintos. O risco é
inteiramente futuro e da espécie quieta — um quinto backend que por acaso
use um nome comum recebe a credencial de produção de outro, e o primeiro
sintoma é falha de autenticação contra o serviço errado ou, pior, uma
chamada **bem-sucedida** feita com a identidade errada.

## Decisão

### 1. O compartilhamento é reportado no boot, e não recusado

A guarda óbvia — recusar quando duas entradas declaram o mesmo nome — seria
errada aqui, e a própria frota de laboratório é a prova: os quatro mocks
leem `MOCK_SECRET` e `MOCK_EXPECT` por desenho, porque um valor de fixture
compartilhado é exatamente o que eles são. Recusar quebraria uma implantação
que funciona para impedir um erro que ninguém cometeu.

O que a GAB-32 nomeia como dano é o **silêncio**. É isso que fecha aqui: o
compartilhamento continua possível e passa a ser visível, então o quinto
backend que queira um nome comum se anuncia no boot que o introduz, em vez
de numa falha de autenticação semanas depois.

### 2. Chavear por `(upstream, variável)` fica registrado como **não feito**, com o motivo

É a correção estrutural e continua sendo a direção certa. Não entra agora
por um motivo de implantação, não de código: mudaria a forma do arquivo de
segredos, e o provisionador que o escreve teria de mudar junto. Em 12 set
2026 essa exata classe de divergência — cofre e registry nomeando coisas
diferentes — derrubou os quatro upstreams num deploy cujo script saiu 0
dizendo "provisioned". Acrescentar uma convenção de chave nova no mesmo
lugar, no mesmo dia, sem ADR, seria repetir o erro com outra roupa.

**E há uma armadilha no desenho óbvio que precisa estar escrita antes de
alguém implementá-lo.** A forma natural é procurar `<upstream>/<VAR>` e cair
para `<VAR>` quando não existir — assim o compartilhamento continua
expressável e nada quebra. Mas então um erro de digitação na chave
específica (`casemgmt/API_TOKN`) cai silenciosamente na chave compartilhada,
e o backend recebe a credencial errada sem uma palavra. É o mesmo defeito
que esta ADR fecha, reintroduzido pela solução dele.

Quem implementar isso tem de fazer **cada resolução por fallback ser
visível** — o boot dizendo quais variáveis resolveram pela chave específica
e quais pela compartilhada. Sem isso, a correção estrutural é uma troca de
um silêncio por outro.

## Consequências

**Impactos positivos:** o dano declarado da GAB-32 — a invisibilidade —
acaba, sem custo de implantação e sem quebrar a frota atual.

**Impactos negativos aceitos:** duas entradas ainda não conseguem ter
valores diferentes sob o mesmo nome. Continua inexpressável, agora de forma
declarada em vez de descoberta.

**O que continua aberto:** a GAB-32 em si. Esta ADR fecha o silêncio, não a
estrutura, e não deve ser lida como tendo fechado a segunda.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: `sharedCredentials` em `cmd/mcp-gateway/serve.go`, com testes
  que exigem o relato de um nome declarado por duas entradas, a ausência de
  relato para nome declarado por uma só, e — o que fixa a decisão de não
  recusar — que a frota de quatro mocks compartilhando dois nomes seja
  reportada e continue subindo.
- Onde vive: `cmd/mcp-gateway/wiring_test.go`.

## Notas

- Autor: Claude, 12 set 2026, fechando a metade da GAB-32 que é fechável
  hoje.
- Depende de `0005` (o cofre é sops, e o arquivo é o que mudaria) e ecoa a
  lição do deploy do mesmo dia: duas listas que precisam concordar, sem nada
  conferindo, concordam até o dia em que não concordam.
