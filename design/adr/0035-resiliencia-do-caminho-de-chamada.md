# 0035. Resiliência do caminho de chamada

**Status:** Accepted — 28 set 2026.

## Contexto

A revisão comparativa de 28 set 2026 confirmou quatro falhas no caminho de
uma chamada. Todas são pequenas, e todas afetam os sete analistas de uma vez:

- **Um panic derrubava o processo.** O go-sdk roda cada handler de
  ferramenta numa goroutine sem `recover` (`internal/jsonrpc2/conn.go`). Um
  adaptador com bug, ou o scrub diante de uma entrada inesperada, encerrava o
  gateway inteiro.
- **Não havia teto de concorrência.** Um agente em paralelo ou um token
  roubado podia ocupar o processo compartilhado de cada backend por até
  `call_timeout` por chamada, e quantas chamadas quisesse.
- **O teto de corpo era o padrão do SDK** (4 MiB), implícito, e mudava com
  uma atualização do SDK.
- **Um token forjado virava um fetch de JWKS.** O go-oidc refaz o fetch sem
  intervalo mínimo sempre que encontra um `kid` desconhecido ou uma
  assinatura inválida. Um chamador anônimo gerava uma requisição ao IdP por
  token.

## Decisão

### 1. Panic vira uma chamada recusada, auditada

`Dispatch` adia um `recover` como primeira instrução. O `dispatchTool` do
httpapi faz o mesmo para o código que roda depois do `Dispatch`, e o
`ServeHTTP` para o resto da requisição. O chamador recebe o erro constante
`internal error`. Na trilha fica a razão `internal error`, e a linha segue a
regra do `0012`:

- antes da linha `allowed`, nada foi despachado, então fica `denied`;
- depois dela, fica `failed`, anotando a `allowed`.

Um panic em `ServeHTTP` antes da autenticação vai só para o log. Se fosse
para a trilha, um anônimo capaz de provocá-lo teria um escritor sem teto, e
o `0027` limita exatamente esse caminho.

O valor do panic nunca é logado nem devolvido, porque pode ser um texto do
upstream ou uma credencial. O log registra o tipo e a stack.
`http.ErrAbortHandler` é relançado.

### 2. Teto de chamadas em voo por analista, sem fila

`[response] max_concurrent_calls_per_analyst`, com padrão 4. Zero ou
negativo é recusado na carga, pela regra de `max_bytes` e `call_timeout`:
não há valor que desligue o teto. Cada `sub` tem um contador em memória.
Uma chamada que encontra o contador cheio é recusada na hora, sem fila,
porque uma fila seguraria a goroutine do mesmo jeito e só mudaria onde o
acúmulo acontece.

A posição no `Dispatch` é **depois do `admit` e antes da quota**:

- depois do `admit`, pelo mesmo motivo da quota (`0030` decisão 5): uma
  ferramenta em quarentena continua indistinguível de uma inexistente;
- antes da quota, porque o débito nunca é revertido, e uma chamada recusada
  por concorrência não pode gastar orçamento;
- antes da linha `allowed`, porque essa linha afirma que houve despacho.

A vaga é devolvida no fim do `Dispatch`, depois da chamada, da checagem do
resultado e do scrub, e também quando há panic.

A recusa vai para a trilha como `denied` / `concurrency limited`. Para o
cliente, ela vira uma classe própria no httpapi, espelhando
`quota exhausted` (`0030` decisão 7): mensagem constante igual à razão, e
429 onde há status HTTP. O que se revela é um fato do próprio chamador.

### 3. Corpo de requisição limitado a 1 MiB, explícito

`httpapi.MaxRequestBodyBytes` é passado ao SDK como `MaxRequestBodyBytes`.
Acima dele, o SDK responde 413 e nada chega ao `Dispatch`. Um `tools/call`
é um nome e poucos argumentos, então 1 MiB fica ordens de grandeza acima do
tráfego real.

### 4. No máximo um fetch de JWKS a cada 30 s

O keyset do go-oidc recebe um cliente HTTP próprio, cujo `RoundTripper`
recusa localmente qualquer fetch a menos de 30 s do anterior. O limite conta
tentativas, não sucessos, para que um IdP falhando também não seja
martelado. A recusa vira uma rejeição comum de token, e as chaves em cache
continuam valendo. A descoberta usa o cliente sem limite.

O custo aparece uma vez por rotação de chave: um token com a chave nova, a
menos de 30 s do último fetch, é recusado até a janela passar. Resolve com
um retry, não é indisponibilidade.

## Consequências

- Um panic custa uma chamada, não o serviço.
- Sete analistas ainda podem somar 28 chamadas em voo. Não há teto global
  nem por backend. Limite de taxa por requisição (`limit_req`) é trabalho
  do proxy reverso.
- Um analista com mais de quatro consultas paralelas legítimas recebe
  `concurrency limited` e precisa aumentar o valor no arquivo.
- Deploy: o template de configuração pode declarar a chave nova. Ausente,
  vale o padrão.

## Compliance

- `internal/gateway`: `TestDispatch_APanickingUpstreamIsAnAuditedFailure`,
  `TestDispatch_ConcurrencyCapRefusesFastWithoutSpendingQuota`,
  `TestNew_ConcurrencyCapDefaultsWhenUnset`.
- `internal/gateway/httpapi`:
  `TestAPanickingUpstreamIsOneFailedCallNotADeadProcess`,
  `TestAPanicBeforeAuthenticationIsTheGeneric500`,
  `TestAPanicAfterAuthenticationIsAuditedToTheCaller`,
  `TestARequestBodyOverTheCapIsRefusedUnread`,
  `TestConcurrencyLimitedIsItsOwnClass`.
- `internal/access/oidc`: `TestForgedTokensDoNotTurnIntoJWKSFetches`.
- `internal/config`: `TestMaxConcurrentCallsCannotDisableTheCap`.
