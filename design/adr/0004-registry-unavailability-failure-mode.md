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

- [ ] Automatizável? Sim, uma vez decidido — teste de integração que força
  falha de leitura do SQLite e confirma o comportamento escolhido.
- Onde vive o teste: a definir.
- Quando roda: a cada build/CI.

## Notas

- Autor: investigação conjunta (bunnyiesart + Claude), 31 Aug 2026, a partir de
  pesquisa comparativa com Envoy/Kong/APISIX/Ory Oathkeeper.
- **Aguardando decisão de bunnyiesart** entre Opção A, Opção B, ou a
  recomendação (A com retry/TTL curto).
