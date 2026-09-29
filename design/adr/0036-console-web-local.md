# 0036. Console web local

**Status:** Accepted — 29 set 2026.

## Contexto

O Operator Console é um conjunto de subcomandos (`design/02-components.md`,
`cmd/mcp-gateway/operator.go`). Para a fila de quarentena isso pesa: revisar
uma tool alterada é ler duas definições e um diff num terminal, e aprovar é
copiar um fingerprint de 64 caracteres para outra linha de comando. O dono
pediu uma interface simples, hospedável em localhost, para operar o Gatte.

Um servidor HTTP em loopback não é tão privado quanto parece. Todo site
aberto no navegador do operador alcança `127.0.0.1`: pode enviar um POST de
formulário para ele (CSRF) e pode apontar um nome que controla para esse
endereço depois que a página carregou (DNS rebinding). E, na VM de
produção, o loopback é compartilhado com todo processo e todo usuário da
máquina.

## Decisão

### 1. Um subcomando, não um serviço

`mcp-gateway ui [-config FILE] [-listen 127.0.0.1:8090]` roda em primeiro
plano, como o usuário de serviço, igual aos outros comandos do console, e
termina com Ctrl-C. Não há unit, nem processo sempre ligado, nem porta
aberta quando ninguém está operando. HTML renderizado no servidor
(`html/template`), CSS embutido no binário, nenhum JavaScript e nenhuma
dependência nova. Fora da máquina, o acesso é por `ssh -L`.

### 2. Cada botão é o comando de mesmo nome

*Revisto por `0040`:* os comandos de mesmo nome chamam agora o serviço de
gestão (`internal/admin`), o mesmo que responde no socket do `mcp-gateway
admin`; a página ainda o chama no próprio processo até virar cliente da API
(`0040` §6), e as defesas desta seção viraram a biblioteca `pkg/frontkit`.

Aprovar chama `runToolApproveFingerprint`, bloquear chama `runAccessBlock`,
verificar a trilha chama `runAuditVerify`, e as listas são os `-json` de
`tool list`, `access list`, `audit`, `upstream list` e `quota usage`. A
página mostra o que o comando imprimiu. Não existe uma segunda
implementação de aprovar, onde a checagem do fingerprint pudesse ser
esquecida.

- O formulário de aprovação leva o fingerprint da definição que a página
  acabou de mostrar, lido na mesma leitura da entrada. Se a tool anunciar
  outra coisa até o clique, o comando recusa (`0032`).
- Registrar, assinar e desregistrar um backend ficam no terminal. Assinar
  precisa da chave de root (`0010`), e desregistrar é destrutivo demais
  para um botão.
- Bloqueio e desbloqueio gravam a mesma linha de operador do CLI (`0031`),
  atribuída a `operatorName()` do processo, com `[ui]` no início da razão.
  Sem isso a trilha não distingue um navegador de um terminal.
- Cada ação lê o arquivo de configuração de novo, como um comando do CLI lê
  a cada execução. O processo pode ficar horas no ar, e grants, signatários
  e orçamentos de quota mudam no arquivo. Um arquivo que deixou de carregar
  recusa a ação.

### 3. As defesas que um terminal não precisava

Na ordem em que a requisição as encontra:

1. **Bind em loopback**, recusado fora disso, sem override (como `0011`).
2. **Host precisa nomear loopback**: `localhost` em qualquer caixa, um
   endereço de `127.0.0.0/8` ou `::1` (inclusive `::ffff:127.0.0.1`). Isso
   derruba DNS rebinding. A porta não é comparada, porque um `ssh -L` pode
   usar qualquer porta local.
3. **Um link de login, uma sessão.** 32 bytes aleatórios, impressos só no
   terminal de quem rodou o comando, como `/login?token=...`. O link vale
   uma vez: pode ficar no histórico do navegador, no scrollback ou num log
   de terminal. Ele abre uma sessão com um id próprio, também aleatório,
   que vai em dois lugares: como primeiro segmento de todo caminho
   (`/s/ID/...`) e num cookie `HttpOnly`, `SameSite=Strict`, com `Path`
   nesse prefixo. Os dois têm de bater, e a sessão acaba em 12 horas.
   Comparações em tempo constante.

   O caminho existe porque cookie não separa porta. Uma página que outro
   processo serve em outra porta de `localhost` é "same site", e o
   navegador entrega a ela o cookie (numa sub-requisição da própria origem
   dela). Ela não conhece o caminho, e sem ele o cookie não vale nada. Isso
   separa o operador dos outros usuários da máquina e dos outros serviços
   no loopback do navegador.
4. **POST com token de formulário por execução** e, quando o navegador
   manda `Origin`, esse `Origin` tem de ser a própria página, comparado sem
   diferenciar caixa. Estado só muda em POST; um GET numa rota de ação
   recebe 405.
5. **Cabeçalhos**: `Content-Security-Policy: default-src 'none';
   style-src 'self'; form-action 'self'; frame-ancestors 'none';
   base-uri 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`
   (a URL carrega o id da sessão), `no-store`.
6. **Texto não confiável escapado duas vezes**: pelo `html/template`, contra
   HTML, e pelo `internal/visible`, para que um code point invisível
   apareça como `\u{XXXX}`, como no CLI. Isso vale também para o que um
   comando imprimiu numa página de resultado, escapado linha a linha, sem
   depender de cada comando ter escapado o que imprime.
7. **A página de auditoria mostra no máximo 5000 registros**, para que uma
   renderização não segure as outras ações.

## Consequências

- Um operador revisa uma tool alterada com o diff colorido e aprova com um
  clique que só vale para o que foi mostrado.
- Quem executa código como o usuário de serviço já tinha todo o poder do
  console (`0003`); a página não muda isso. Outro usuário da máquina alcança
  a porta, mas não tem o link nem a sessão.
- Não protege contra quem lê o perfil do navegador do operador (histórico e
  cookies juntos). A máquina que abre o console é a do operador.
- Uma sessão por execução. Fechar o navegador ou passar das 12 horas pede
  reiniciar o `ui` para um link novo; parar o `ui` encerra a sessão.
- Sem TLS: o tráfego fica no loopback, ou dentro do túnel ssh. Por isso o
  cookie não leva `Secure` (nem todo navegador o envia a
  `http://localhost`), e o gosec aponta isso (G124); a proteção dele é
  `HttpOnly` e `SameSite=Strict`.
- Não resolve: quem aprovou uma tool continua fora da trilha (`0032`), e a
  página não julga o texto pelo operador. *Revisto por `0040`:* aprovar e
  revogar passam a gravar `(tool approve)` e `(tool revoke)`, pelo CLI, pela
  página e pela API.

## Testes

`cmd/mcp-gateway/ui_test.go`: bind fora de loopback recusado; o link de
login abre uma sessão uma vez só; o cookie sem o caminho da sessão (e o
caminho sem o cookie) não vale; a sessão acaba; Host que não é loopback
recusado; `Origin` em outra caixa é a mesma origem; cada ação relê a
configuração; o limite da auditoria é 5000; a página de resultado escapa o
que o comando imprimiu; POST sem token de
formulário ou de outra origem não muda nada; GET numa ação não muda nada;
bloqueio e desbloqueio viram as linhas de operador com `[ui]`; a revisão
escapa um U+202E e só aprova o fingerprint mostrado; tabelas escapam texto
não confiável; toda página leva a CSP e nenhuma leva script.
