# 0001. Monolithic, domain-partitioned ("modular monolith") architecture for the custom MCP gateway

**Status:** Proposed

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
- Onde vive o teste: a definir na implementação — `07-fitness-functions.md`
  do dev-context recomenda algo equivalente a ArchUnit/NetArchTest; a
  ferramenta concreta depende da linguagem escolhida (`0002`).
- Quando roda: a cada build/CI, não sob demanda.
- Mudanças de código necessárias: nenhuma além de definir as interfaces dos
  8 componentes como parte da implementação inicial.

## Notas

- Autor: investigação conjunta (bunnyiesart + Claude), decisão registrada 31 Aug 2026.
- Aprovado por: pendente confirmação de bunnyiesart.
