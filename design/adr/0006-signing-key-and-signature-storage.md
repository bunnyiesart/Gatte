# 0006. Chave de assinatura em arquivo próprio, assinaturas em tabela separada

**Status:** Accepted

## Contexto

`design/adr/0003-security-controls.md` decidiu **o quê**: assinatura Ed25519
das entradas de registro, padrão Wirken, com hash canônico que exclui
valores de segredo. O que ele não resolveu, e a Fase 3 (`WORKFLOW.md`)
precisa resolver antes da primeira linha de código: **onde vive a chave
privada de assinatura, e onde vive a assinatura resultante.**

Duas perguntas pequenas em aparência, mas ambas mexem com material
criptográfico no componente cuja razão de existir é integridade — logo,
significativas o bastante para um ADR e não para um comentário no código
(`04-adrs.md` §2, critério "estrutura" e "características não-funcionais").

## Decisão

### 1. A chave privada fica em arquivo próprio, fora do banco

Um arquivo Ed25519 no host, permissão apenas para o dono, caminho passado
por configuração — **não** no SQLite, **não** no `Credential Vault`.

Fora do SQLite porque `design/adr/0001` já diz que o banco embarcado nunca
guarda segredo, e uma chave de assinatura é exatamente isso. Fora do
`Credential Vault` por uma razão menos óbvia: o Vault existe para resolver
credenciais **de upstreams** em memória no momento do spawn. A chave de
assinatura tem ciclo de vida, dono e momento de uso completamente
diferentes — é usada pelo Operator ao registrar uma entrada, não pelo
gateway ao atender uma chamada. Misturar as duas daria ao caminho de
requisição acesso a material que ele nunca precisa tocar, e o
desintegrador "isolamento de segurança" de `design/02-components.md` é
justamente o que mantém `Credential Vault` e `Definition Signer`
separados.

### 2. As assinaturas ficam em tabela própria, não como coluna do registro

Uma tabela do `Definition Signer`, chaveada pelo nome da entrada, em vez de
uma coluna `signature` em `upstream_servers`.

O registro é *dado de configuração*; a assinatura é uma *afirmação sobre*
esse dado, feita por outro componente, com outro dono. Colocá-la como
coluna faria o adapter do `Upstream Registry` (Fase 1, já pronto e testado)
mudar de forma toda vez que o esquema de assinatura evoluir, e daria ao
código do registro a possibilidade de escrever no campo que deveria
atestá-lo.

### 3. O hash canônico inclui `Name`, além do que o `0003` enumera

`0003` lista "command/url + args + nomes de env var". A implementação
inclui também o **nome da entrada**, e o acréscimo é deliberado.

Sem ele, a assinatura atesta *o que se executa*, mas não *qual entrada
manda executar*. Duas entradas com o mesmo comando, args e nomes de env
var — plausível entre um `casemgmt` legítimo e um `casemgmt-staging` criado por
quem tenha escrita no banco — produziriam o mesmo hash, e a linha de
assinatura de uma serviria para a outra. Incluir `Name` liga a assinatura
à entrada específica e fecha esse transplante.

Custo real: zero. Renomear uma entrada é deregister + register, que já
exige nova assinatura de qualquer forma.

A codificação é **TLV com prefixo de tamanho** (`uint64be(len) || bytes`
por campo, contagem antes de cada lista), com uma tag de domínio
versionada (`mcp-gateway/signer/canonical/v1`) no início. Não é
preciosismo: concatenação ingênua faz `Command "docker" + Args ["run"]`
colidir com `Command "dockerrun" + Args []`, e uma colisão dessas é vetor
de forja de assinatura, não detalhe estético. A tag versionada existe
para que uma mudança futura de formato não deixe assinaturas velhas e
novas silenciosamente intercambiáveis.

### 4. Verificação no boot recusa entrada inválida, não entrada ausente

Assinatura **inválida** (não bate com o conteúdo) é recusa: a entrada não é
servida. Assinatura **ausente** é decidida por configuração — o modo
"anchored" do Wirken, desligado por padrão nesta fase.

A assimetria é deliberada. Uma assinatura que não confere é evidência
positiva de adulteração e não tem leitura benigna. Uma assinatura ausente,
enquanto o `Operator Console` (Fase 6) não existe para criar assinaturas
com ergonomia, é o estado normal de toda entrada — falhar fechado nela
agora tornaria o gateway impossível de usar antes da Fase 6, sem ganho de
segurança real, porque não há ainda nenhum fluxo que produza assinaturas em
volume.

**Isto é dívida declarada, com data:** quando a Fase 6 entregar o fluxo de
assinatura, o padrão deve inverter para exigir assinatura. Registrado aqui
para não virar um default esquecido — que é exatamente a falha que este
projeto encontrou em cinco dos seis candidatos avaliados.

## Consequências

**Impactos positivos:** o esquema da Fase 1 não muda; `Definition Signer`
é adicionável e removível sem tocar no `Upstream Registry`; nenhum material
criptográfico entra no SQLite; o caminho de requisição não tem acesso à
chave de assinatura.

**Impactos negativos aceitos:** mais um arquivo com permissão restrita
para operar no host (somando-se à identidade age do `0005`) — o problema
"secret zero" de novo, com o mesmo raio de dano limitado e a mesma
resposta: menos coisas em texto claro, não zero. Ler entrada + assinatura
passa a ser duas consultas em vez de uma; irrelevante no volume desta
equipe.

**Trade-offs assumidos:** trocamos "uma consulta" por "componentes que não
se contaminam", coerente com a ordem de prioridade de
`design/01-discovery.md` (Segurança acima de simplicidade de
implementação, e ambas acima de performance, que aqui nem é fator).

## Compliance

- [x] Automatizável? Sim, parcialmente.
- Mecanismo: a fitness function existente
  (`TestOnlyCompositionRootImportsAdapters`) já impede que qualquer
  pacote fora do composition root alcance o adapter do signer
  diretamente. O teste de rotação (`0003`) prova que a assinatura
  sobrevive à troca de credencial — que é o que a exclusão de valores do
  hash canônico existe para garantir.
- O que **não** é automatizável: a permissão do arquivo de chave no host.
  Fica em `deploy/freebsd-jail.md` como pré-requisito verificado à mão.

## Notas

- Autor: Claude, 08 Sep 2026, início da Fase 3.
- Depende de `0001` (SQLite nunca guarda segredo), `0003` (Ed25519,
  padrão Wirken, hash sem valores) e `0005` (precedente de ferramenta e
  chave externas ao módulo Go).
