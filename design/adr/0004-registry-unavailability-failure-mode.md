# 0004. Failure mode when Upstream Registry is unreadable

**Status:** Accepted — decided by bunnyiesart, 31 Aug 2026: fail closed with
short retry (the recommendation below)

## Contexto

Surgiu de comparação com prática estabelecida de API gateways
(`DEVELOPMENT-LOG.md` §10.2): um operador de Envoy relatou incidente em que
uma dependência caiu, o control plane empurrou uma tabela de rotas vazia, e
o Envoy corretamente-mas-inutilmente devolveu 503 para toda rota, em vez de
servir a última configuração boa conhecida.

`Upstream Registry` (`design/02-components.md`) guarda em SQLite quais
servidores upstream existem e como alcançá-los. `03-style.md` já aceitou
que um crash do processo derruba o gateway inteiro (SPOF, um quantum só) —
mas nunca decidiu o que `Gateway Endpoint` faz especificamente se o arquivo
SQLite estiver momentaneamente ilegível ou corrompido *sem* o processo
inteiro cair (disco cheio, I/O lento, corrupção pontual).

## Alternativas

### Opção A — Fail closed

| Prós | Contras |
|---|---|
| Nunca serve uma decisão de roteamento baseada em dado potencialmente errado; nunca contorna acidentalmente uma quarentena por estar usando estado desatualizado | Uma falha de leitura breve no SQLite (não o processo inteiro) já basta para derrubar acesso de **todo** analista a **todos** os quatro backends |
| Mais simples de implementar e de raciocinar sobre | Amplifica o SPOF já aceito em `0001` — um problema de disco, não só um crash de processo, agora também é incidente total |

### Opção B — Servir última configuração boa conhecida (in-memory cache)

| Prós | Contras |
|---|---|
| Uma falha de leitura breve não interrompe o trabalho do analista | Se um servidor foi removido do registro (ou uma tool foi movida para `changed`/quarentena) exatamente durante a janela de indisponibilidade, o cache em memória pode servir uma decisão de roteamento **já revogada** — contradiz diretamente `Tool Quarantine` (`02-components.md`), cuja garantia é que uma tool `changed` fica bloqueada imediatamente |
| Mais alinhado com "simplicidade & deployability" do ponto de vista do analista (nunca vê a falha) | Mais um componente de estado (o cache) para manter correto e para testar |

## Decisão

**Vamos falhar fechado, com retry curto.** Enquanto `Upstream Registry`
estiver ilegível, `Gateway Endpoint` não serve nenhuma tool — trata como
indisponibilidade total, não como "usar o que tinha antes." O processo
tenta reler em intervalo curto (a definir na implementação, ordem de
segundos) em vez de cachear indefinidamente um estado que não consegue
confirmar como válido.

> **CORREÇÃO, 09 set 2026 — o retry não existe. Só metade desta decisão
> foi implementada.**
>
> `Gateway.Connect` é chamado **exatamente uma vez**, em
> `cmd/mcp-gateway/serve.go`, durante o arranque. Não há laço, não há
> temporizador, não há intervalo "da ordem de segundos" em lugar nenhum do
> código. As consequências reais, que são diferentes das descritas acima:
>
> - **Falha do registro no boot é fatal.** O processo não sobe. Isso é
>   fail-closed, e é a metade que funciona — deliberadamente, com
>   justificativa escrita no próprio `serve.go`: um processo que escuta na
>   porta e não serve nada para ninguém é pior que um que se recusa a
>   subir, porque só o segundo é visível para quem o reiniciou.
> - **Mudança no registro depois do boot é invisível até reiniciar.** Não
>   só uma falha de I/O: uma entrada registrada, removida ou re-assinada
>   com o gateway no ar não muda nada até o próximo `serve`.
> - **Portanto o cenário que motivou este ADR — "o arquivo SQLite fica
>   ilegível por alguns segundos com o processo no ar" — não tem hoje
>   comportamento nenhum.** Não falha fechado *durante* a janela e não
>   relê depois dela; simplesmente não olha. A tabela de rotas montada no
>   boot continua servindo.
>
> Note que o terceiro ponto é uma forma de exatamente o que a Opção B foi
> rejeitada por permitir: servir uma decisão de roteamento que já não se
> consegue confirmar. Chegamos nele por omissão, não por escolha — o que é
> pior que ter escolhido.
>
> **Isto precisa de uma das duas coisas, e não de mais um documento que
> descreva o retry como se ele existisse:** ou implementar a releitura
> periódica que esta decisão manda, ou um ADR novo que largue o retry
> explicitamente e diga por quê. O argumento honesto a favor de largar,
> verificado no código: a garantia da quarentena — que era o motivo da
> urgência aqui — **não depende da tabela de rotas**. `Dispatch` consulta
> `quarantine.Get` contra o banco a cada chamada, então uma ferramenta
> marcada `changed` fica bloqueada imediatamente, com ou sem releitura do
> registro. O que a tabela de rotas velha ainda permite é servir um
> upstream *desregistrado*, que é uma classe menos grave. Se esse for o
> raciocínio, ele merece estar escrito num ADR e não deduzido daqui.
>
> Não foi rastreado como item até 09 set 2026; está sendo agora.

**Justificativa técnica:** entre as duas opções, só a Opção A garante que
`Tool Quarantine` nunca é contornado por estar servindo uma decisão de
roteamento desatualizada — uma tool marcada `changed` durante a janela de
indisponibilidade nunca seria servida por engano, porque nada é servido.
O retry curto (em vez de fail-closed permanente) evita que uma falha de
disco breve vire um incidente de turno inteiro sem necessidade.

**Justificativa de negócio:** entre Segurança e Simplicidade &
deployability — as duas colidindo de verdade pela primeira vez desde
`01-discovery.md` — bunnyiesart priorizou Segurança: melhor um analista esperar
alguns segundos numa falha rara de disco do que o gateway servir, mesmo que
por uma janela curta, uma tool que acabou de ser revogada por suspeita de
poisoning.

## Consequências

**Impactos positivos:** nenhuma janela em que uma revogação de quarentena
possa ser ignorada; comportamento do sistema fácil de explicar ("se o
registro não pode ser lido com confiança, nada é servido").

**Impactos negativos aceitos:** uma falha de disco breve (segundos) já
interrompe o trabalho de **todos** os analistas simultaneamente — o SPOF
já aceito em `0001` fica mais fácil de disparar, não só por crash de
processo mas por qualquer soluço de I/O no arquivo SQLite. Aceito porque a
alternativa (servir estado potencialmente revogado) contradiz diretamente
a garantia central de `Tool Quarantine`.

**Trade-offs assumidos:** trocamos disponibilidade (evitar toda
interrupção visível ao analista) por garantia de que quarentena nunca é
contornada por estado desatualizado — decisão explícita de bunnyiesart dado o
conflito Segurança vs. Simplicidade nomeado acima.

## Compliance

- [x] Automatizável? Sim — teste de integração que força falha de leitura
  do SQLite e confirma o comportamento.
- Onde vive o teste (preenchido em 09 set 2026 — era "a definir"):
  - `TestConnect_RegistryFailureFailsClosed`,
    `internal/gateway/gateway_test.go`: prova que a tabela de rotas é
    derrubada e nada é servido.
  - `TestBuildServer_UnreadableRegistryIsFatal`,
    `cmd/mcp-gateway/serve_test.go`: prova a mesma coisa no nível do
    arranque, que é onde ela de fato acontece. **Pula, não falha**, sem
    `sops` no PATH — ver o aviso do `make test`.
- **Cobertura parcial, e a parte que falta é a que diverge.** Os dois
  testes acima cobrem só a metade fail-closed. Não existe teste do retry,
  porque não existe retry — ver a correção de 09 set 2026 na Decisão. Esta
  seção dizia que o teste confirmava "o comportamento escolhido"; confirma
  metade dele.
- Quando roda: a cada build/CI.

## Notas

- Autor: investigação conjunta (bunnyiesart + Claude), 31 Aug 2026, a partir de
  pesquisa comparativa com Envoy/Kong/APISIX/Ory Oathkeeper.
- Decidido por bunnyiesart em 31 Aug 2026: Opção A com retry curto (ver
  Status). Esta linha dizia "**Aguardando decisão de bunnyiesart**" sob um
  Status `Accepted` até 09 set 2026 — contradição de arquivo, não decisão
  em aberto. A pendência real deste ADR não é a decisão, é a
  implementação: ver a correção na seção Decisão.
