# 0013. Quarentena: re-observação periódica e semântica de remoção

**Status:** Accepted

## Contexto

O `0007` decidiu a semântica da Tool Quarantine e continua valendo em tudo
o que decidiu. O que ele não previu são duas ausências que a revisão de
09 set 2026 encontrou, e que juntas deixam o componente sem metade do seu
ciclo de vida.

### 1. A detecção de rug pull não pode disparar num gateway em execução

`quarantine.Store.Observe` — a única coisa que avança `ObservedHash` — é
chamada de um lugar só, dentro de `Gateway.Connect`. E `Connect` é chamado
de um lugar só: uma vez, no arranque.

Não há ticker, não há SIGHUP, e o cliente MCP é construído com opções
nulas, então a notificação `notifications/tools/list_changed` é ignorada.

Enquanto isso o código afirma o contrário: *"a tool that flips to changed
stops being served immediately rather than at the next refresh"*. **Não
existe next refresh.** Um backend que reescreve a descrição de uma tool às
09:00 só é re-medido quando alguém reinicia o processo — o que num gateway
de SOC pode ser semanas. O componente construído para pegar tool poisoning
(OWASP MCP03) não dispara enquanto o gateway faz o seu trabalho.

Vale ser preciso sobre o que **funciona**: a releitura por chamada
(`admit` → `Usable()`) pega corretamente o que um *operador* muda pelo CLI,
então `tool approve` vale sem reiniciar. O que não funciona é perceber o
upstream mudando por baixo.

### 2. A quarentena não tem remoção nenhuma

Verificado no código: `internal/quarantine` não expõe delete, remove,
forget nem revoke, e `runUpstreamDeregister` só apaga a assinatura.

Dois sintomas, uma causa:

- **Aprovação sobrevive ao deregister.** Reproduzido na implantação viva:
  um upstream removido e registrado de novo — entrada diferente, lista de
  env diferente, assinatura nova — teve as três tools ainda `approved` e
  servíveis na hora. A quarentena nunca viu um upstream novo. O operador
  revisou a entrada A e a entrada B está servindo sob a aprovação de A.
- **Aprovar é caminho de mão única.** Não existe `tool revoke`. O único
  caminho de volta para `pending` é apagar o banco.

## Decisão

### 1. Re-observação periódica, com intervalo configurável

`Gateway.Refresh(ctx)` re-executa `tools/list` contra os upstreams
conectados e passa o resultado por `Observe`, e o `serve` chama isso num
ticker.

**Por que ticker e não `list_changed`:** a notificação é mais barata e
quase instantânea, e depende inteiramente da cooperação do upstream. Um
backend comprometido simplesmente não a envia — e backend comprometido é o
cenário inteiro deste componente. Então a notificação, se um dia for
implementada, é otimização em cima do ticker, nunca substituição dele.
Escrito aqui para que ninguém "simplifique" depois trocando um pelo outro.

O intervalo é configuração porque o custo é real: cada refresh é um
`tools/list` por upstream. Padrão conservador, e um valor que desliga a
re-observação **não existe** — quem não quiser pagar o custo aumenta o
intervalo, e essa escolha fica visível no arquivo em vez de virar um
booleano que alguém desliga "por um minuto".

Um refresh que falha contra um upstream **não** derruba nada e não altera
estado: falhar em medir não é evidência de que algo mudou, e tratar as duas
coisas como iguais transformaria uma indisponibilidade de rede em uma
quarentena em massa. Fica no log, e a medição anterior permanece.

### 2. Remoção: `Forget` por upstream, `Revoke` por tool

- **`Forget(upstream)`**, chamado pelo `deregister`. Remover um upstream
  passa a remover o que foi dito sobre ele, exatamente como já remove a
  assinatura dele. Mesma lição do `0006` item 3 e do GAB-25: estado que
  sobrevive à remoção da coisa que ele descrevia acaba avalizando um
  substituto.
- **`Revoke(upstream, tool)`**, exposto como `mcp-gateway tool revoke`,
  devolve uma tool para `pending`.

O `0007` diz que `changed` é permanente **até um humano aprovar**, e isso
não muda: `Revoke` é a ação de um humano retirando um julgamento que ele
mesmo fez, que é a outra metade da mesma ideia.

> **Emenda na implementação — 09 set 2026.** Este ADR dizia "devolve uma
> tool para `pending`" sem qualificar o estado de origem, e a implementação
> **recusa** `Revoke` sobre uma tool em `changed`. A emenda está certa e
> fica.
>
> `changed` não é "não revisada": é *rug pull registrado*. Levá-la para
> `pending` apagaria essa distinção, transformando um alarme num item que
> ninguém olhou ainda — destruindo justamente o registro permanente que a
> regra 1 do `0007` existe para preservar, e apagando o bloco de aviso que
> o `tool list` imprime.
>
> E não compraria nada: uma tool em `changed` **já** é inservível. O
> movimento que o operador quer ali é aprovar deliberadamente (assumindo o
> risco, com as duas impressões digitais na frente dele) ou remover o
> upstream — não fingir que o alarme não tocou. Sem ela, a resposta a
incidente não tem o movimento mais óbvio — desconfiei desta tool, pare de
servi-la — e o gate `Usable()` já é relido por chamada, então o efeito é
imediato.

### 3. O que a impressão digital não pega, e por isso o teste certo

O fingerprint de definição continua pegando tool cuja *definição* mudou.
O que escapa é um substituto anunciando definições **idênticas** — que é
exatamente o que um atacante trocando o binário de um backend arranjaria,
já que a lista de tools é a parte que ele controla.

Portanto o teste do `deregister` é: registrar de novo o mesmo nome com
definições **idênticas** e exigir que as tools estejam `pending`. Um teste
com definições diferentes passaria mesmo sem `Forget`, pelo fingerprint, e
não provaria nada.

## Consequências

**Impactos positivos:** o componente passa a ter o ciclo de vida completo —
observa, e volta a observar; aprova, e desaprova; esquece o que deixou de
existir. E o comentário que afirmava imediatismo passa a ser verdade em vez
de aspiração.

**Impactos negativos aceitos:** um `tools/list` por upstream por intervalo,
para sempre — custo pequeno nesta frota e não zero; e mais dois métodos na
porta, que é superfície que precisa continuar coerente.

**O que continua em aberto:** entre dois refreshes existe uma janela em que
uma tool envenenada é servida. Encurtá-la é baixar o intervalo, e isso é
troca explícita, não bug. E nada aqui protege o banco de quem tem escrita
nele — mesma conversa do `0010` e do `0012`.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: um teste que muda a definição de uma tool **num upstream já
  conectado**, dispara `Refresh`, e exige que ela pare de ser servível sem
  reiniciar nada — escrito primeiro contra o código atual, onde ela
  continua servível, que é o defeito. Mais o teste de `deregister` com
  definições idênticas descrito no item 3, e um de `Revoke` provando que a
  tool para de ser servida na chamada seguinte.
- Onde vive: `internal/gateway/gateway_test.go`,
  `internal/quarantine/quarantine_test.go`,
  `cmd/mcp-gateway/tool_test.go`.

## Notas

- Autor: Claude, 09 set 2026, a partir de GAB-23 e GAB-33.
- Estende `0007` sem contradizê-lo. Depende de `0004` (falhar em medir não
  é o mesmo que medir uma falha) e do precedente de `0006` item 3 sobre
  estado que sobrevive ao que descrevia.
