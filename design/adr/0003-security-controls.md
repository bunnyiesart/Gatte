# 0003. Security controls: sops+age credential injection, per-tool quarantine, Ed25519 definition signing

**Status:** Accepted — 09 set 2026.

> **Ressalva de implementação, não da decisão.** Dos três controles que
> este ADR decide, dois estão em vigor: injeção sops+age (`internal/vault`,
> Fase 2) e quarentena por ferramenta (`internal/quarantine`, chamada por
> `gateway.Connect`, Fase 3/5). O terceiro — **assinatura Ed25519 das
> entradas, verificada no boot** — foi construído e testado
> (`internal/signer`), mas **nada fora do próprio pacote o invoca**:
> `gateway.Connect` lê o registro e disca sem verificar assinatura
> nenhuma. A decisão está aceita; o controle ainda não está ligado.
> Rastreado como item próprio.

## Contexto

"Security" foi a primeira característica priorizada (`design/01-discovery.md`)
e é a razão de existir deste projeto — as cinco alternativas testadas
falharam justamente aqui (`DEVELOPMENT-LOG.md` §5). Três mecanismos
concretos precisam de decisão: como os segredos ficam disponíveis para os
servidores upstream sem tocar disco/log; como novos servidores/tools são
aprovados antes de ficarem visíveis; como detectar alteração numa definição
de tool já aprovada (rug-pull, OWASP MCP03).

## Decisão

**Vamos usar três mecanismos, cada um confirmado por leitura direta do
código-fonte de um candidato testado (`DEVELOPMENT-LOG.md` §9.2, §9.3):**

1. **Credential Vault com `sops` + `age`.** Um `Provider` (interface
   inspirada em `pkg/secrets/types.go` do ToolHive) resolve uma referência
   de segredo para o valor real, em memória, no momento do spawn de cada
   servidor upstream — nunca gravado em disco nem logado. A chave privada
   `age` fica num arquivo root-only no host do gateway; o arquivo de
   segredos criptografado é seguro para versionar em Git privado.
2. **Tool Quarantine por tool, não por servidor.** SHA-256 sobre
   `nome + descrição + schema de entrada` de cada tool (padrão
   mcpproxy-go). Servidor novo → toda tool nasce `pending`, invisível e
   não-chamável até aprovação do Operador. Tool já aprovada cujo hash
   muda → `changed`, mesmo bloqueio — cobre rug-pull em servidor já
   confiado, não só onboarding.
3. **Assinatura Ed25519 das entradas de registro** (padrão Wirken), com o
   hash cobrindo `command/url + args + nomes de variáveis de ambiente` —
   **excluindo os valores dos segredos**, para que rotacionar uma
   credencial nunca invalide a assinatura.

**Justificativa técnica:** os três mecanismos foram lidos diretamente do
código-fonte dos projetos que os implementam corretamente (não das docs),
então a decisão não é "vamos inventar algo parecido" — é "vamos reimplementar
um mecanismo já comprovado, com as adaptações já identificadas na pesquisa"
(sops+age no lugar do vault com senha interativa do ToolHive; granularidade
por-tool no lugar de por-servidor onde o mcpproxy-go já é assim; hash que
exclui segredo, exatamente como o Wirken faz).

**Justificativa de negócio:** o gap de segurança é a razão de negócio para
todo o projeto existir — não adotar um produto pronto porque nenhum
resolvia isto. Entregar um mecanismo mais fraco que o que a pesquisa já
provou funcionar (em outro projeto) seria repetir o erro que descartou as
cinco alternativas.

## Consequências

**Impactos positivos:** nenhum segredo em disco fora do arquivo cifrado por
`sops`; nenhum servidor/tool novo aparece para analistas sem aprovação
humana explícita; alteração indevida numa definição já aprovada é detectada
antes da próxima chamada, não depois de um incidente.

**Impactos negativos aceitos:** a chave privada `age` continua sendo um
arquivo em texto claro no host do gateway — comprime N cópias (uma por
laptop de analista) para 1 arquivo root-only, mas não é criptografia real
"em uso." Pesquisa (`DEVELOPMENT-LOG.md` §9.3) confirma que nenhuma opção
sem infraestrutura de KMS externa resolve isso completamente — aceito
porque o objetivo real (§3) é sair de N cópias para 1, não atingir
segurança de HSM. Quarentena por tool adiciona fricção deliberada a cada
onboarding — extensibilidade fica mais lenta por design (já registrado em
`01-discovery.md`, "known conflicts").

**Trade-offs assumidos:** trocamos velocidade de onboarding de novos
servidores/tools por garantia de que nada entra sem revisão — decisão
direta da priorização de Segurança acima de Extensibilidade em
`01-discovery.md`.

**Atualização 31 Aug 2026 (Round 5, `DEVELOPMENT-LOG.md` §10.2):** prevenção
de token passthrough deixa de ser item em aberto e vira quarto mecanismo
desta ADR — **credential stripping em `Access Control`, antes de qualquer
chamada upstream**, no padrão `hide_credentials` do Kong: a credencial
apresentada pelo cliente é explicitamente removida da requisição antes de
`Gateway Endpoint` repassar a chamada, e o `Credential Vault` injeta a
credencial própria do gateway separadamente. Isto é passo distinto de
*injetar* — sem ele, minting de credencial própria não impede que a
credencial do cliente ainda vaze junto na mesma chamada.

**O que isto NÃO cobre** (§9.4 do `DEVELOPMENT-LOG.md` — precisa de
mecanismo próprio, não incluído aqui):
- Telemetria/observabilidade (OWASP MCP08) — o `Audit Trail`
  (`02-components.md`) cobre "quem chamou o quê," não métricas
  operacionais.
- Validação de schema nas *respostas* das tools antes de reentrarem no
  contexto do modelo (mitigação separada para prompt-injection via
  resultado, citada na pesquisa mas fora do escopo desta ADR).

## Compliance

- [x] Automatizável? Sim, para os três mecanismos.
- Mecanismo: testes de integração que (a) confirmam que um segredo nunca
  aparece em nenhum log/arquivo fora do vault cifrado; (b) confirmam que
  uma tool `pending`/`changed` não aparece na listagem nem é executável;
  (c) confirmam que verificação de assinatura roda no boot e recusa
  entradas alteradas quando em modo anchored.
- Onde vive o teste: a definir na implementação.
- Quando roda: a cada build/CI.
- Mudanças de código necessárias: nenhuma além da própria implementação
  dos três mecanismos.

## Notas

- Autor: investigação conjunta (bunnyiesart + Claude), 31 Aug 2026.
- Depende de `0002` (linguagem) para a escolha de bibliotecas concretas
  (`sops`/`age`, `cryptography`/Ed25519, `hashlib`) — mecanismo em si é
  independente da linguagem.
