# 0011. Exposição de rede: loopback obrigatório, TLS no proxy, VPN como única rota

**Status:** Accepted

## Contexto

A terceira fase de teste muda a natureza do que se está testando. As duas
primeiras rodaram o gateway como **processo local**: `internal/e2e` sobe a
pilha inteira em memória, e a jail provou que o binário roda em FreeBSD.
Nenhuma das duas exercitou o gateway como **serviço de rede**.

bunnyiesart definiu a terceira fase em 09 set 2026: **uma máquina de fora
alcança um serviço na jail, e o único caminho é uma VPN.**

Isso força três decisões que estavam adiadas por não terem consequência
enquanto tudo era loopback. E força a pior delas primeiro: hoje
`warnIfNotLoopback` (`cmd/mcp-gateway/serve.go`) **avisa e continua**. Um
operador que troca `listen` para `0.0.0.0:8080` para "deixar um colega
testar" recebe uma linha de log e, depois dela, o token OIDC de cada
analista em texto claro na rede — junto de dados de caso e IOCs.

Vale ser desconfortável a respeito: "seguro até você mudar uma string, e aí
silenciosamente não" é exatamente a fraqueza de modo padrão que reprovou
dois dos seis candidatos externos avaliados (`DEVELOPMENT-LOG.md` §3). Ser
julgado pelo próprio critério é o mínimo.

## Decisão

### 1. O gateway recusa qualquer bind que não seja loopback

Não avisa: **recusa, no arranque**, com mensagem dizendo o que fazer.

O gateway deixa de ter opinião sobre TLS porque deixa de estar exposto.
Ele não termina TLS, não carrega certificado, não tem `listen_tls`. A
única coisa que ele garante é que não há como alcançá-lo de fora do host
sem passar por outra coisa.

Isso é mais restritivo do que "avise bem alto", e a diferença é o ponto:
um aviso é uma decisão delegada a quem tem pressa. Uma recusa é uma
decisão que já foi tomada por quem estava pensando no assunto.

### 2. TLS é terminado por um proxy reverso **na mesma jail**

Consequência direta do item 1, e a parte que é fácil errar: se o gateway
só aceita loopback, o proxy precisa **compartilhar esse loopback**. Em
bastille cada jail tem seu próprio `127.0.0.1`, então proxy e gateway na
mesma jail se enxergam; proxy em outra jail teria de falar com o IP da
jail do gateway, que é justamente o que o item 1 proíbe.

Portanto: `nginx` e `mcp-gateway` moram na jail `mcp-gateway-test`. O nginx
escuta o IP da jail em 443 com TLS; o gateway escuta `127.0.0.1:8080`.

> **CORREÇÃO — 09 set 2026, no mesmo dia. A premissa acima é falsa.**
>
> "Cada jail tem seu próprio `127.0.0.1`" está **errado** para jail
> clássica (não-VNET), que é o que este laboratório usa. Uma jail clássica
> não tem loopback próprio: ela recebe um conjunto de endereços, e um
> processo que faz bind em `127.0.0.1` tem esse bind **reescrito para o
> endereço roteável da jail**.
>
> Medido, não deduzido. Dentro de `mcp-gateway-test`:
>
> ```
> $ nc -l 127.0.0.1 18080 &
> $ sockstat -4 -l | grep 18080
> root  nc  32734  3  tcp4  10.17.89.10:18080  *:*
> ```
>
> e de fora da jail, `nc -z 10.17.89.10 18080` **conecta**.
>
> A consequência é exatamente a classe de defeito que este ADR foi escrito
> para fechar: `requireLoopbackBind` passa, o log diz `listen=127.0.0.1:8080`,
> o operador acredita que o gateway só é alcançável pelo nginx — e o
> gateway está escutando em texto claro no IP que o cliente da VPN alcança,
> contornando o TLS inteiro. O mesmo vale para a Authelia, encontrada
> escutando `10.17.89.20:9091` em HTTP simples com `address:
> 'tcp://127.0.0.1:9091'` escrito na configuração dela.
>
> **O que continua valendo:** recusar bind não-loopback continua correto e
> continua sendo a coisa certa a fazer no binário. O erro não é o controle,
> é ter afirmado que ele **basta**. Numa jail clássica nenhum bind é
> inalcançável, então nenhuma checagem de endereço dentro do processo pode
> entregar esta propriedade — é uma restrição do ambiente, não do código.
>
> **O que precisa mudar na implantação**, em ordem de preferência:
>
> 1. **Jail VNET** para o gateway. Pilha de rede própria, `127.0.0.1` de
>    verdade, e aí o item 1 entrega o que promete sem nada além.
> 2. **Endereço de loopback dedicado** (`lo0|127.0.1.10`) somado aos
>    endereços da jail, com o gateway fazendo bind nele. `127/8` não é
>    roteado pela VPN, e `IsLoopback()` já aceita, então não exige mudança
>    de código. Mais leve que VNET.
> 3. **pf** bloqueando `10.17.89.10:8080` vindo de fora do host. Funciona,
>    mas é convenção verificada em outro lugar — precisamente o que o item
>    1 queria deixar de ser.
>
> **RESOLVIDO no mesmo dia — opção (1), jail VNET.** Escolha de bunnyiesart.
> `mcp-gateway-test` virou jail VNET com pilha de rede própria, em
> `10.17.90.10/24` atrás da bridge `socbr0`. O teste de aceitação é o bloco
> de medição acima dando o resultado oposto, e dá:
>
> ```
> $ bastille cmd mcp-gateway-test sockstat -4 -l | grep 18080
> root  nc  13801  3  tcp4  127.0.0.1:18080  *:*      <- não mais reescrito
>
> controle: 10.17.90.10:18081 alcançável do host da VM  -> OK
> 10.17.90.10:18080 do host da VM                       -> recusado
> 127.0.0.1:18080 no host da VM                         -> silencioso
> 10.17.90.10:18080 de dentro da jail authelia          -> recusado
> ```
>
> O **controle** importa tanto quanto a negativa: sem ele, o teste passaria
> igual numa jail com rede quebrada. Verificado por mim de forma
> independente, não só pelo relato de quem implementou.
>
> **A sub-rede teve de mudar**, e a razão é a mesma coisa que causou o
> defeito: `bastille0` é clone de loopback, os endereços das jails clássicas
> são aliases `/32` nele, e não há camada 2 onde prender um epair. Uma jail
> VNET em `10.17.89.10/24` trataria `10.17.89.20` como *on-link*, faria ARP
> pela Authelia numa bridge onde ninguém responde, e a descoberta OIDC
> falharia no arranque do gateway. Em `10.17.90.0/24` a Authelia fica
> off-link, sai pela rota default, e o host encaminha — e é aqui que
> `net.inet.ip.forwarding`, ligado antes por precaução, deixa de ser
> decorativo.
>
> Três consequências, todas tratadas: `/etc/hosts` das jails, a rota
> `10.17.90.0/24` empurrada pela VPN, e o SAN do certificado do nginx, que
> precisa carregar `IP:10.17.90.10`.
>
> Sobrevive a `jm stop`/`jm start` sem passo manual, e o rollback foi
> **executado**, não só escrito: reverte para jail clássica e o defeito
> volta a ser mensurável, o que é a prova de que o rollback reverte a coisa
> certa.
>
> **O que continua não verificado:** que um cliente na ponta da VPN alcança
> `10.17.90.10` — a segunda rota está empurrada e o openvpn reiniciou
> limpo, mas isso é esperado, não medido, até alguém conectar o túnel.

Escolhido em vez de terminar TLS no próprio binário porque mantém material
de certificado e renovação fora do processo que detém todas as credenciais
de backend — o mesmo raciocínio de isolamento que o `0006` usa para manter
a chave de assinatura fora do Credential Vault. O custo é honesto: mais uma
peça para operar, contra a característica #3.

### 3. A VPN é a única rota, e não é considerada suficiente sozinha

OpenVPN. A jail não recebe porta publicada para a rede geral; quem chega,
chega pelo túnel.

**A VPN não substitui o TLS do item 2, e isso é deliberado.** O túnel
protege máquina-a-máquina; dentro da rede da jail o tráfego ainda
atravessa um segmento onde outra jail, ou o host, poderia observá-lo. Duas
camadas aqui não é paranoia gratuita — é a diferença entre "o token do
analista está protegido do mundo" e "o token do analista está protegido de
tudo, inclusive do que compartilha o mesmo host".

### 4. O provedor OIDC roda em jail própria

Authelia em `authelia` (jail separada), não junto do gateway.

O `0008` já registrou que o IdP é "um serviço com estado a mais" e que ele
pode ser *ele* o que quebra às 3h da manhã. Domínio de falha separado é o
que permite reiniciar um sem derrubar o outro — o que importa mais aqui do
que em geral, porque o `0008` também registrou que o gateway **não sobe**
com o IdP inalcançável. Juntar os dois transformaria "o IdP caiu" em "os
dois caíram, e o gateway não volta até o IdP voltar".

O IdP precisa ser alcançável de dois lados: do cliente na ponta da VPN
(para *obter* token) e do gateway (para o JWKS, no arranque). Ambos pela
VPN.

## Consequências

**Impactos positivos:** a exposição de rede passa a ser uma propriedade
verificada no arranque em vez de uma convenção. O gateway fica com uma
superfície menor — nenhum código de TLS, nenhum certificado, nenhuma
renovação. E a topologia passa a ser testável de verdade: máquina externa,
túnel, proxy, gateway, quatro backends.

**Impactos negativos aceitos:** duas peças novas para operar (nginx e
OpenVPN) mais uma jail nova, em uma equipe sem função de plataforma —
puxando de novo contra a característica #3, pelo segundo ADR seguido. E o
item 1 remove uma configuração que hoje funciona: quem quisesse o gateway
escutando direto na rede não consegue mais, nem com aviso.

**Deliberadamente sem escotilha de saída.** Não existe
`allow_insecure_bind = true`. Uma opção dessas seria ligada uma vez "só
para testar" e nunca desligada — é o mecanismo exato pelo qual o
`require_signed` apodreceria se o `0006` não tivesse gatilho escrito. Se
um dia terminar TLS no gateway for a decisão certa, isso é emenda a este
ADR com `listen_tls` de verdade, não uma flag que desliga a checagem.

**O que isto não resolve:** nada aqui autentica a máquina externa além do
que a VPN e o token OIDC já fazem. Um laptop autorizado e comprometido
continua sendo um cliente legítimo com um token legítimo — o que é
exatamente o que o Audit Trail existe para tornar reconstituível, e uma
razão a mais para o endereço de origem que falta nos registros (ISSUE-24).

## Compliance

- [x] Automatizável? Sim, a parte do gateway.
- Mecanismo: teste de que `serve` recusa `0.0.0.0`, um IP concreto de
  interface, e `[::]`, e aceita `127.0.0.1` e `[::1]` — escrito primeiro
  contra o código atual, onde passa, para que a recusa seja evidência.
- Onde vive: `cmd/mcp-gateway/serve_test.go`.
- O que **não** é automatizável daqui: que o nginx realmente termine TLS,
  que a jail não tenha porta publicada, e que a VPN seja a única rota.
  Isso é verificação de implantação e vive em `deploy/`, conferido à mão
  pelo probe rodando da máquina externa.

## Notas

- Autor: Claude, 09 set 2026. Topologia decidida por bunnyiesart (OpenVPN,
  Authelia em jail própria, TLS no proxy reverso).
- Fecha a metade de gateway do ISSUE-27. Depende de `0001` (um processo),
  `0006` (precedente de isolar material sensível) e `0008` (IdP como
  serviço separado, e o acoplamento de arranque).
