# 0008. Modelo de identidade: OIDC auto-hospedado, gateway como Resource Server

**Status:** Accepted

## Contexto

Pergunta em aberto desde o documento de decisão original (§10 Q4), sinalizada
em `WORKFLOW.md` como bloqueio explícito da Fase 4: **"tokens estáticos
nomeados bastam para 7 pessoas, a menos que já exista um IdP"** — nunca
resolvida, e proibida de ser assumida ("don't assume static tokens").

bunnyiesart definiu em 08 Sep 2026 a restrição que resolve a pergunta:
**tudo precisa ser auto-hospedável.** Isso elimina de saída as duas opções
que a análise anterior considerava as únicas que justificariam OIDC
(Google Workspace, Entra) — ambas SaaS, ambas já barradas pelo mesmo
raciocínio LGPD/egresso que eliminou metade do mercado de gateways
(`DEVELOPMENT-LOG.md` §3).

Restaram duas: tokens estáticos nomeados (nada a hospedar) ou um provedor
OIDC auto-hospedado.

## Decisão

**OIDC auto-hospedado.** O gateway passa a ser um **OAuth 2.0 Resource
Server**: não emite identidade, apenas valida tokens emitidos por um
provedor que a equipe hospeda.

**Contra a recomendação registrada anteriormente**, e vale dizer por quê,
para que ninguém releia a análise antiga e ache que foi ignorada por
descuido: a análise de segurança de 26 Ago concluiu que tokens estáticos
bastavam nesta escala e desaconselhou subir um IdP para 7 pessoas; o peso
operacional de um Keycloak foi, inclusive, parte do que reprovou o
`mcp-gateway-registry` (§10.1a). Essa análise não estava errada sobre o
custo — bunnyiesart a pesou e escolheu pagar, por identidade central e
offboarding em um lugar só.

### O gateway não escolhe o provedor

A validação OIDC é **agnóstica de provedor**: descoberta via
`/.well-known/openid-configuration`, chaves via JWKS, validação de
assinatura, emissor, audiência e expiração. Nada disso é específico de
Keycloak, Authelia ou Zitadel.

Portanto **qual IdP rodar é decisão de implantação, não de código.** O
gateway recebe issuer, audiência esperada e o nome do claim que carrega os
grupos; nada além disso entra no código.

**Recomendação de implantação, não vinculante:** Authelia — binário Go
único, SQLite, usuários em arquivo, provedor OIDC completo. É a coisa mais
leve que ainda é um provedor OIDC de verdade, e mantém a característica
#3 (`Simplicity & deployability`) tão intacta quanto esta decisão permite.
Keycloak e Zitadel funcionam igual do ponto de vista do gateway, ao custo
de um banco de dados a mais para operar.

### Biblioteca: `go-oidc`, não implementação própria

`github.com/coreos/go-oidc/v3` para descoberta, JWKS e verificação.

Coerente com `0005`, mas chegando na conclusão oposta, e a diferença
importa: lá, `sops` trazia SDKs de quatro nuvens que este projeto nunca
usa, e o que se ganhava embutindo era conveniência. Aqui, o que se
escreveria à mão é rotação de chave JWKS, cache, e verificação de
assinatura JWT — plumbing criptográfico onde implementação própria é
notoriamente onde os bugs moram, e onde "funciona nos meus testes" e
"está correto" divergem silenciosamente.

Superfície real medida antes de decidir: `golang-jwt/jwt/v5` e
`golang.org/x/oauth2` **já estão** no grafo de módulos (transitivos do SDK
oficial de MCP); `go-oidc` acrescenta `go-jose` e nada mais. Nenhum SDK de
nuvem, nenhum banco, nada que se pareça com o que reprovou o `sops`
embutido.

A regra dos dois ADRs é a mesma, e não é "menos dependências sempre": é
**não importar superfície que não se usa, e não reescrever à mão o que é
fácil de errar em silêncio.**

### O que essa escolha passa a exigir (que tokens estáticos não exigiriam)

Ao virar Resource Server, os requisitos de nível **MUST** da própria spec
do MCP (`DEVELOPMENT-LOG.md` §9.1) deixam de ser hipotéticos:

- Validar **audiência** do token via Resource Indicators (RFC 8707) — um
  token emitido para outro serviço do mesmo IdP não pode valer aqui.
- Aceitar credencial **apenas** em `Authorization: Bearer`, nunca em
  parâmetro de URL.
- OAuth 2.0 Protected Resource Metadata (RFC 9728) quando existir endpoint
  HTTP (Fase 5).
- Tokens de vida curta (SHOULD).
- **ID de sessão nunca vale como autenticação** — cada requisição é
  verificada de forma independente.

Isso é mais trabalho que tokens estáticos, e é também alinhamento com a
spec que tokens estáticos jamais dariam. Conta como ganho, não só custo.

### O que continua valendo, independente do IdP

`design/adr/0003` já exige **credential stripping**: a credencial que o
cliente apresenta é removida antes de qualquer chamada upstream, e o
gateway cunha a sua própria. Um token OIDC do analista **nunca** é
repassado a um backend — passthrough é proibido pela spec em nível MUST, e
quebraria a atribuição por analista que é a característica #2 deste
projeto.

## Consequências

**Impactos positivos:** identidade real e central; offboarding em um lugar
só; mapeamento grupo → papel vem do IdP em vez de uma lista mantida à mão;
conformidade com os MUSTs da spec; e, por ser agnóstico, trocar de provedor
depois não é reescrita.

**Impactos negativos aceitos:** um serviço com estado a mais para uma
equipe sem função de plataforma — atualizações, backup e a possibilidade
real de ser *ele* o que quebra às 3h da manhã e impede todo mundo de
autenticar. Puxa diretamente contra a característica #3. O gateway ganha
uma dependência de runtime que não tinha: se o IdP está fora, ninguém
autentica.

> **Observado ao rodar o binário de verdade, 09 set 2026.** O acoplamento
> acima é mais forte no *arranque* do que em regime: a descoberta OIDC
> acontece antes de o gateway servir qualquer coisa, então **um IdP
> inacessível impede o processo de subir**, não apenas de autenticar.
>
> Isso está correto e é intencional — subir sem poder validar token
> nenhum significaria responder 401 a todo mundo, o que não é serviço, é
> ruído. Mas a consequência operacional merece estar escrita: o cache de
> JWKS cobre uma queda *transitória do IdP com o gateway já no ar*; ele
> não cobre "IdP fora **e** gateway reiniciado", porque aí não há cache.
> Nesse cenário a recuperação é ordenada: o IdP volta primeiro, o gateway
> depois.
>
> Para quem opera: não reinicie o gateway durante uma janela de manutenção
> do IdP a menos que pretenda que ele fique fora até o IdP voltar.

**Mitigação obrigatória na Fase 4:** o comportamento do gateway quando o
IdP está inacessível precisa ser decidido explicitamente, não descoberto
em produção. Fail closed é a escolha coerente com `0004` (mesmo raciocínio
da indisponibilidade do registro), mas cache de JWKS com TTL é o que
impede que uma indisponibilidade momentânea do IdP derrube a operação
inteira — JWKS muda raramente, e validar assinatura com chave em cache é
seguro enquanto a chave não foi revogada.

**Trade-offs assumidos:** trocamos simplicidade operacional por identidade
central e conformidade com a spec. É a primeira decisão deste projeto que
inverte a prioridade #3 em favor da #1 e da #2 — legítimo, dado que
Segurança e Auditabilidade estão acima dela, mas registrado como inversão
consciente e não como esquecimento.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: testes de validação com um JWKS de teste próprio — token
  expirado, audiência errada, emissor errado, assinatura inválida, alg
  `none`, e token válido — todos herméticos, sem IdP rodando. **Isto
  existe e roda.**
- Onde vive: `internal/access/oidc/oidc_test.go` (o verificador e a
  descoberta) e `internal/access/access_test.go` (papéis, audiência,
  `TestIdentity_CarriesNoCredentialField`). Esta linha apontava para
  `internal/access/*_test.go` até 09 set 2026, o que deixa de fora o
  pacote onde o verificador de fato mora.

> **CORREÇÃO, 09 set 2026 — o teste contra um IdP real nunca foi escrito.**
>
> Esta seção prometia, além dos testes herméticos, "um teste end-to-end
> contra um provedor real, que **pula com aviso** quando não há um
> configurado, seguindo exatamente o padrão de `0005`". Não existe: não há
> teste algum no repositório condicionado a um IdP configurado, nem
> variável de ambiente que o ligue, nem `t.Skip` correspondente. O padrão
> do `0005` foi citado, não copiado.
>
> O que isso deixa **não** coberto, e vale nomear em vez de deixar a
> promessa não cumprida escondida numa lista: os testes herméticos usam um
> JWKS que este repositório mesmo gera. Eles provam que a *lógica* de
> validação está correta — expiração, audiência, emissor, `alg`. Não
> provam interoperabilidade com um provedor de verdade: descoberta em
> `/.well-known/openid-configuration` com os campos que um Keycloak ou
> Authentik realmente emitem, rotação de JWKS em produção, a forma
> concreta do claim de grupos. Esse último é o mais provável de morder —
> `TestVerifyGroupsClaim` cobre as formas que *nós supusemos*, contra um
> emissor que *nós escrevemos*; `groups_claim` é configurável exatamente
> porque provedores discordam, e a discordância real não está no
> repositório para ser exercitada.
>
> A Fase 6 cobriu parte disso à mão, rodando o binário: `serve` se recusa
> a subir contra um emissor inalcançável (`WORKFLOW.md` Fase 6). É
> verificação manual, feita uma vez, e não substitui o teste prometido.
> Escrever o teste, ou riscar a promessa por decisão explícita, é item em
> aberto.

## Notas

- Autor: decisão de bunnyiesart, 08 Sep 2026; ADR redigido por Claude.
- Resolve o Q4 em aberto desde o documento de decisão original e
  desbloqueia a Fase 4.
- Depende de `0003` (credential stripping continua obrigatório) e
  `0004` (precedente de fail-closed).
