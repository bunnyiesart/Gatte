# 0026. O critério de v1: o que a terceira condição queria, e o que a substitui

**Status:** Accepted — 16 set 2026.

## Contexto

O `WORKFLOW.md` define o fim do v1 em três condições: as sete fases marcadas,
todo ADR em `Accepted`, e *"o harness do `lab/` rodado contra o build
terminado (o checkpoint da Fase 5, repetido depois das Fases 6–7)"*.

As duas primeiras estão satisfeitas e são verificáveis num comando. A
terceira **nunca foi satisfazível como escrita**, e isso não é uma
descoberta de última hora: a Fase 5 a define dizendo que `make lab-probe`
faz o trabalho, e esse alvo roda

    ./bin/lab/probe --tool <name>_credcheck -- ./bin/lab/<name>

ou seja, a sonda conversando por stdio **direto com cada mock**, sem gateway
nenhum no caminho. O `deploy/gateway-serve.md` diz isso em voz alta na linha
355: *"run `lab/probe` against a mock directly — that is what it is for, and
it does not need the gateway"*. Dois arquivos deste repositório afirmavam
coisas opostas sobre o mesmo comando, e o que estava errado era o que define
o critério de pronto.

## Alternativas

### Opção A — Construir o alvo que a frase descreve

Um alvo que põe o gateway entre o `lab/probe` e os quatro mocks: sobe o
binário com cofre e IdP de teste, registra, assina, aprova, e aponta a sonda
para o endpoint HTTP.

| Prós | Contras |
|---|---|
| O `lab/probe` é um cliente **diferente** dos usados nos testes, e isso tem valor próprio: um segundo implementador do protocolo encontra o que um só não encontra | Precisa de IdP e cofre reais fora de um teste Go — trabalho de uma tarde, e mais um mundo a manter em paralelo com o deploy |
| Satisfaz a condição na letra | O que ele provaria já está provado por outros meios (abaixo), então o ganho é o cliente diferente e não a propriedade |

### Opção B — Reescrever a condição para o que de fato a satisfaz (escolhida)

| Prós | Contras |
|---|---|
| A propriedade **está** provada, e por caminhos mais fortes que o descrito | Perde-se o segundo implementador do protocolo, e isso é uma perda real |
| O critério passa a nomear provas que existem e rodam em `make check` | Um leitor pode ler isto como o critério sendo afrouxado para caber no que foi feito |

O segundo contra é o risco sério desta decisão, e a resposta a ele é o item 3.

## Decisão

**Opção B**, com a Opção A registrada como trabalho arquivado e não como
recusa.

### 1. A condição passa a nomear o que prova, e o que cada prova cobre

A terceira condição vira: *o harness do `lab/` rodado ponta a ponta contra o
build terminado, provado por*

- **`internal/e2e`** — quatro mocks compilados e spawnados como
  subprocessos reais, registry SQLite real, quarentena real, trilha real,
  dialer stdio real, superfície HTTP real e um cliente MCP real do outro
  lado. Cobre a propriedade central (credencial injetada chega ao backend e
  não volta ao cliente) e, desde 15 set, a mudança de frota com o gateway
  servindo.
- **`TestBuildServer_DeliversAVaultSecretToARealBackend`** — o que o
  `internal/e2e` deliberadamente não faz: atravessar a **raiz de
  composição**. Cofre sops+age em disco, provedor OIDC cujo token o
  verificador real aceita, entrada registrada pelo console do operador,
  backend spawnado, uma chamada por HTTP, e a impressão digital comparada
  com o sha256 do segredo que o teste cifrou.
- **`internal/vault/sopsage`** — o leak check contra sops e age reais, que o
  `Makefile` já descreve como a prova ponta a ponta de que um segredo
  resolvido não chega ao cliente de um upstream.

Juntos cobrem mais do que a frase original pedia. O que nenhum deles faz é
usar o `lab/probe` como cliente.

### 2. A Fase 5 deixa de afirmar o que `make lab-probe` não faz

A frase da Fase 5 é corrigida no lugar, com o registro de que esteve errada
— é como este repositório trata correção, e apagá-la esconderia que o
critério de pronto ficou apoiado numa afirmação falsa desde a Fase 5 até
16 set 2026.

### 3. A Opção A vira trabalho arquivado, com o motivo dela escrito

Não é recusada. O argumento a favor dela **não é** "a propriedade não está
provada" — está. É que o `lab/probe` é outro implementador do protocolo, e
dois implementadores acham o que um não acha. Isso continua verdade depois
desta decisão, e por isso a Opção A fica no `WORKFLOW.md` como item
arquivado, com esta frase junto: *quem a construir não está refazendo prova,
está acrescentando um segundo cliente*.

Registrar assim é o que impede esta decisão de ser uma redução do critério
disfarçada de esclarecimento.

### 4. O que o v1 NÃO passa a afirmar

Nada sobre a implantação. As provas acima rodam nesta máquina, e **11 testes
de topo em `cmd/mcp-gateway` e 9 em `internal/vault/sopsage` pulam em
silêncio** num host sem `sops` e `age` — o `make test` prepende o
`GOPATH/bin` e por isso os encontra aqui. Um v1 declarado onde essas
ferramentas faltam é um v1 cujas provas de processo não rodaram, e isso fica
escrito no bloco do critério em vez de virar surpresa.

Nada sobre a jail: o que roda em produção foi provisionado por scripts cuja
última execução conhecida é de 12 set 2026, antes de cinco ADRs.

## Consequências

**Impactos positivos:** o critério de v1 passa a ser verificável por quem ler
o repositório, com nomes de teste que existem e um comando que os roda.

**Impactos negativos aceitos:** o `lab/probe` continua sem ser exercido
contra o gateway, e a diferença entre "um cliente prova" e "dois clientes
provam" fica em aberto — declarada, não fechada.

## Compliance

- [x] Automatizável? Em parte, e a parte automatizável é nova: o
  `TestCitedTestsExist` em `internal/fitness/manifest_test.go` falha se um
  documento nomear um teste que não existe — que é como duas seções de
  Compliance deste repositório passaram a apontar para o vazio (ADR-0023 e
  ADR-0025), em dias diferentes, escritas pela mesma pessoa.
- O que não é automatizável é a leitura do critério em si, e esta ADR existe
  para que ela não precise ser refeita do zero pelo próximo.

## Notas

- Autor: bunnyiesart + Claude, 16 set 2026.
- A decisão de reescrever em vez de construir é de bunnyiesart; o
  `WORKFLOW.md` já dizia, sobre esta mesma frase, que consertá-la é *"uma
  decisão de bunnyiesart, não uma linha para editar silenciosamente até
  concordar"*.
