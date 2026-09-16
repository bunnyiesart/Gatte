# 0025. Toda chamada a um backend tem prazo, e o prazo é do gateway

**Status:** Accepted — 16 set 2026.

## Contexto

`Gateway.Dispatch` entrega `ctx` direto ao `up.CallTool`, e esse `ctx` é o
da requisição HTTP do analista. Duas coisas decorrem disso, e nenhuma estava
escrita:

1. **Não há teto de tempo.** Um backend que aceita a chamada e não responde
   segura a goroutine, a conexão stdio e o slot daquele upstream
   indefinidamente. Nada no processo impõe limite: o `serve.go` tem
   `refreshTimeout`, `reconcileTimeout`, `shutdownTimeout`,
   `readHeaderTimeout` e o prazo da escrita de auditoria — e nenhum prazo
   por chamada.
2. **O cancelamento do cliente é a única saída, e ela não é confiável.** Se
   o analista desiste, o `ctx` do request é cancelado e a chamada termina —
   mas isso depende de o cliente fechar a conexão, de o proxy propagar, e do
   `nginx` na frente, cujo `proxy_read_timeout` padrão é 60 s e que a
   implantação sobe com valores maiores para acomodar chamadas longas. Um
   cliente que some sem fechar (rede que cai, laptop que dorme) deixa a
   chamada pendurada.

A auditoria de 16 set 2026 verificou as duas metades. Nenhum dos 24 ADRs
anteriores decide sobre prazo por chamada: a ADR-0012 *pressupõe* que
`upstream timed out` acontece — a razão de auditoria existe e é testada —
sem nada no sistema que o produza, exceto um cancelamento vindo de fora.

## Alternativas

### Opção A — Continuar sem prazo, e declarar

| Prós | Contras |
|---|---|
| Nenhuma chamada legítima é cortada por um número escolhido no escuro | Uma ferramenta de busca lenta e um backend travado ficam indistinguíveis, para sempre, e o segundo consome recurso até o processo reiniciar |
| Zero configuração nova | A razão `upstream timed out` continua sendo uma promessa que nada cumpre |

### Opção B — Prazo fixo no código

| Prós | Contras |
|---|---|
| Sem chave nova; impossível desligar | Backends deste time respondem em segundos, mas uma varredura de threat intel pode levar minutos, e um número escolhido aqui erraria para alguém sem recurso |

### Opção C — Prazo configurável, sem chave de desligar (escolhida)

| Prós | Contras |
|---|---|
| Mesma forma que `response.max_bytes` já tem: default sensato, mínimo que barra o erro de digitação, e nenhum valor que desligue | Mais uma chave no arquivo, e a escolha do default é um palpite informado |
| O cancelamento do cliente continua valendo — o prazo é um teto, não um substituto | Uma chamada legítima e muito lenta passa a falhar onde antes pendurava; é o ponto, e é uma mudança de comportamento |

## Decisão

**Opção C.** `Dispatch` deriva um contexto com prazo antes de chamar o
upstream, com o valor vindo de `[response] call_timeout`.

### 1. O prazo é do gateway, não do cliente

Derivado do `ctx` da requisição, então **o cancelamento do analista continua
cortando a chamada imediatamente** — o prazo só acrescenta um teto para
quando esse cancelamento não vem. Os dois mecanismos não competem: o que
chegar primeiro vence.

### 2. Default de 2 minutos, mínimo de 1 segundo, sem desligar

Dois minutos é acima de qualquer chamada que os quatro backends deste time
produzem hoje e abaixo do ponto em que um analista já desistiu. O mínimo de
um segundo existe pelo mesmo motivo que `MinResultBytes`: barrar o erro de
digitação que transforma um teto em apagão, não policiar gosto.

Não há valor que desligue, pela regra que este arquivo de configuração já
aplica duas vezes (`quarantine.refresh_interval`, `response.max_bytes`):
zero ou negativo é recusado no arranque, com a mensagem dizendo o que fazer.
Quem precisa de mais tempo aumenta o número, e essa escolha fica legível no
arquivo em vez de virar um booleano que alguém desliga durante um incidente.

### 3. O estouro é uma falha auditada, não uma recusa

`context.DeadlineExceeded` já é classificado como `upstream timed out` por
`classifyFailure`, e a ADR-0012 já manda escrever a segunda linha
`OutcomeFailed` para uma chamada que não voltou. Ou seja: **este ADR não
acrescenta caminho de auditoria nenhum**, ele passa a produzir o evento que
aquela razão sempre descreveu e que nada gerava.

### 4. O que ele não resolve

Não é limite de concorrência. Um analista autorizado que dispare muitas
chamadas lentas ainda ocupa um slot por chamada em cada backend, e o teto
apenas garante que cada slot se libera em tempo finito. Limitar
concorrência por identidade é outra decisão, não tomada aqui, e fica
declarada em `AGENTS.md` §2.

Não é prazo de dial nem de listagem: o arranque tem `DefaultConnectTimeout`
e o laço tem os seus. Este é o caminho do analista.

## Consequências

**Impactos positivos:** um backend travado deixa de segurar recurso para
sempre; a razão `upstream timed out` passa a ter causa dentro do sistema; e
um analista recebe erro em vez de espera indefinida.

**Impactos negativos aceitos:**

- **Uma chamada legítima mais lenta que o teto passa a falhar.** É uma
  mudança de comportamento, e o número é um palpite informado sobre uma
  frota de quatro backends. Quem for mordido aumenta a chave — e o fato de
  precisar aumentá-la é a informação.
- **Mais uma chave.** Terceira com a mesma forma, o que é argumento a favor:
  quem já entendeu `max_bytes` entende esta sem ler nada.

## Compliance

- [x] Automatizável? Sim.
- Onde vivem os testes, em `internal/gateway/reconcile_test.go`:
  - `TestDispatch_ACallThatOutlivesItsDeadlineIsCutAndAudited` — o upstream
    dorme além do prazo, a chamada volta com `context.DeadlineExceeded`, e a
    trilha registra `upstream timed out`.
  - `TestDispatch_TheCallerStillCutsItsOwnCall` — o cancelamento do cliente
    continua valendo antes do prazo. (Esta linha nomeava
    `TestDispatch_TheDeadlineDoesNotOutliveTheCaller`, que nunca existiu: o
    teste foi escrito com outro nome e a ADR ficou apontando para o vazio
    por um dia. É a sexta ocorrência do mesmo formato de defeito neste
    repositório, e a que motivou o portão automatizado em
    `internal/fitness/manifest_test.go`.)
- E em `internal/config/config_test.go`: `TestCallTimeoutDefaultsWhenUnset`,
  `TestCallTimeoutIsRead`, `TestCallTimeoutCannotDisableTheCeiling` e
  `TestCallTimeoutRejectsABareIntegerMeantAsSeconds` — a mesma forma das
  outras duas chaves. (Esta linha prometia esses testes antes de eles
  existirem, e o arquivo citado acima estava errado: duas afirmações falsas
  numa seção de Compliance escrita no mesmo dia em que a ADR-0023 ganhou um
  bloco de correção pelo mesmo motivo.)
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 16 set 2026, a partir de uma auditoria do
  sistema inteiro — a primeira que não olhou um diff.
