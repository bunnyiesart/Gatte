# 0001. Monolithic, domain-partitioned ("modular monolith") architecture for the custom MCP gateway

**Status:** Accepted — implementado por inteiro nas Fases 1–5 (um binário,
um processo, um SQLite embarcado, nenhum salto de rede entre componentes).
Marcado `Accepted` em 09 set 2026 na revisão de pendências; estava
`Proposed` apenas por não ter sido revisitado depois da implementação.

## Contexto

Após rejeitar as cinco opções de gateway testadas (`DEVELOPMENT-LOG.md` §5–6,
todas com defeito de segurança desqualificante em modo padrão), decidimos
construir um gateway próprio. A primeira decisão significativa é o estilo
arquitetural: monolítico ou distribuído, e camadas técnicas ou domínio.
Alternativas consideradas: monolito em camadas, monolito modular,
microkernel, baseado em serviços, microsserviços — análise completa em
`design/03-style.md`.

## Decisão

**Vamos construir um monolito modular, particionado por domínio**, com oito
componentes (`design/02-components.md`): `Gateway Endpoint`,
`Access Control`, `Credential Vault`, `Upstream Registry`,
`Tool Quarantine`, `Definition Signer`, `Audit Trail`, `Operator Console`.
Um processo, um binário, comunicação síncrona interna, um SQLite embutido
para registro/quarentena/auditoria (não para segredos).

**Justificativa técnica:** análise de quantum (`design/03-style.md`, Q1)
mostrou que nenhum dos oito componentes precisa de características
operacionais divergentes o bastante para justificar um segundo quantum —
segurança e auditabilidade se aplicam uniformemente a toda chamada, e o
único candidato a split (`Operator Console`, uso esporádico) foi rejeitado
por não ter perfil de carga que justifique isolamento.

**Justificativa de negócio:** o time que vai operar isto é o mesmo que já
opera os quatro servidores MCP atuais — sem equipe de plataforma, ~7
pessoas. Cada quantum adicional é um processo a mais que essa equipe precisa
saber diagnosticar às 2h da manhã. Reduzir para um quantum reduz
diretamente o custo operacional de longo prazo, que é a característica
"simplicidade & deployability" priorizada por bunnyiesart em 31 Aug 2026.

## Consequências

**Impactos positivos:** deploy de um binário único; nenhuma chamada de rede
entre nossos próprios componentes (elimina 3 das 8 falácias da computação
distribuída para o núcleo do sistema); fronteiras de módulo alinhadas a
responsabilidade de domínio, não a camada técnica, facilitando teste
isolado por componente.

**Impactos negativos aceitos:** elasticidade e tolerância a falha ficam
fracas por definição do estilo — um crash derruba o gateway inteiro, e com
ele o acesso de todos os analistas aos quatro backends simultaneamente.
Isso já está registrado como risco no documento de decisão original (§12).
Modularidade é frágil sem governança — nada impede, no nível de linguagem,
que `Gateway Endpoint` importe `Credential Vault` diretamente, pulando a
interface pretendida.

**Trade-offs assumidos:** trocamos tolerância a falha (que um estilo
distribuído daria) por simplicidade operacional e menor superfície de
falha de rede, porque a equipe que opera isto não tem — e não vai ter —
capacidade de operar um sistema distribuído. Reavaliar se a equipe crescer
com um papel de plataforma dedicado, ou se o volume de chamadas exigir
escalar partes independentemente (nenhum sinal disso hoje).

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: fitness function de dependência entre módulos (nenhum
  componente acessa `Credential Vault` fora da interface pública dele).
- Onde vive o teste (preenchido em 09 set 2026 — era "a definir na
  implementação"): `internal/fitness/fitness_test.go`, três funções que
  varrem o AST do próprio repositório —
  `TestOnlyAdaptersTouchTheDatabase`,
  `TestDomainPackagesDoNotImportTheirOwnAdapter` e
  `TestOnlyCompositionRootImportsAdapters` (esta última é a que sustenta a
  regra do `cmd/mcp-gateway` ser o único lugar que instancia um adaptador
  concreto). Sem ArchUnit/NetArchTest: em Go, `go/parser` sobre o próprio
  módulo é suficiente e não adiciona dependência.
- A regra saiu **mais geral** do que foi escrita aqui. Este ADR pediu a
  fitness function só para o `Credential Vault`; o que existe vale para os
  oito componentes, porque a checagem é estrutural (nada fora de `cmd/`
  importa um pacote abaixo de um pacote de domínio) e não uma lista de
  nomes. O caso do vault é uma instância dela: `internal/vault/sopsage` é
  inalcançável de qualquer lugar que não seja a raiz de composição.
  A outra metade — que um segredo já resolvido não vaza para o processo
  filho — não é estrutural e tem teste próprio,
  `TestResolveThenSpawnDoesNotLeak` em `internal/vault/sopsage/leak_test.go`.
- **Correção de 11 set 2026 — ser um tipo distinto não era guarda nenhuma.**
  Esta seção tratava `vault.Secret` como se o tipo já resolvesse a pergunta
  "alguém fora da interface pública lê o valor?". Não resolvia: a fitness
  function é estrutural (quem importa quem) e não vê o que o `fmt` faz por
  reflexão. `Secret` era um struct com um campo `string` não exportado e
  nenhum método de renderização, então `%v`, `%+v`, `%#v`, `%s` e
  `slog.Any` imprimiam a chave em claro — `Value()` era um de seis caminhos
  para o texto puro, não o único, e a frase "the only path" no doc comment
  afirmava um controle que o código não entregava. Nenhuma chamada da
  árvore formatava um `Secret`, então nada vazou; o que faltava era a
  guarda que faz o *próximo* `slog.Any("cred", s)` quebrar o build em vez
  de vazar uma chave de produção em silêncio. Fechado por
  `String`/`GoString`/`LogValue`/`MarshalText` mais o valor atrás de um
  ponteiro (um método não é alcançável quando o `Secret` está num campo
  não exportado de outro struct — ali o `fmt` reflete direto na
  representação, que por isso precisa ser um endereço). Teste:
  `TestSecretNeverRendersPlaintext` em `internal/vault/redaction_test.go`.
  O que continua **não** garantido, e a frase no código foi estreitada para
  dizer isso: quem for atrás do campo com `reflect`+`unsafe` lê o valor, e
  nenhuma representação em processo impede isso.
- **Cuidado com o cache:** `go test` pode devolver um `pass` velho para
  estes testes mesmo depois de o código violar a regra, porque o arquivo
  varrido não é entrada declarada do teste. Por isso o `make test` usa
  `-count=1`; um `go test ./...` cru não é evidência aqui.
- Quando roda: a cada build/CI, não sob demanda.
- Mudanças de código necessárias: nenhuma além de definir as interfaces dos
  8 componentes como parte da implementação inicial.

## Notas

- Autor: investigação conjunta (bunnyiesart + Claude), decisão registrada 31 Aug 2026.
- Aprovado por: bunnyiesart. Esta linha dizia "pendente confirmação de bunnyiesart"
  sob um Status `Accepted` até 09 set 2026 — contradição de arquivo. A
  confirmação veio junto com a autorização de implementação em 08 set 2026
  (`AGENTS.md` §3), e as seis fases construídas desde então foram
  construídas sobre este estilo.
