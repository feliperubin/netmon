

## Trabalho 2 - Descrição

O trabalho consiste em implementar ferramentas usando socket raw para realização de monitoramento passivo e ativo na rede. O código e funcionamento das ferramentas deverão ser apresentados em sala de aula.  O trabalho pode ser realizado individualmente ou em duplas. Um representante de cada grupo deve submeter no Moodle antes da apresentação um arquivo zip contendo o código-fonte das ferramentas contendo um arquivo README explicando como utilizar cada ferramenta.

### Ferramenta para monitoração passiva

A ferramenta deve monitorar pacotes Ethernet, ARP, IP, ICMP, TCP e UDP. Para cada pacote monitorado, devem ser apresentadas as principais informações de cada cabeçalho:

- Ethernet: endereços MAC origem e destino, tipo do pacote
- ARP: ARP request/reply, endereços MAC origem e destino, endereços IP origem e destino
- IP: endereços IP origem e destino, protocolo encapsulado, TTL
- TCP: portas origem e destino
- UDP: portas origem e destino

Além disso, a ferramenta deve gerar as seguintes estatísticas no término da monitoração (quando for solicitado o término da ferramenta através de Control+C):

- quantidade de pacotes monitorados
- porcentagem de pacotes por protocolo
- tamanhos mínimo e máximo dos pacotes
- 5 IPs que mais enviaram pacotes
- 5 IPS que mais receberam pacotes
- incluir mais 2 estatísticas que acharem interessante

### Ferramenta para monitoração ativa

A ferramenta deve submeter pacotes para verificar a atividade de hosts na rede. A ferramenta deve receber como entrada um endereço de rede (com CIDR) e um intervalo de portas. Se o endereço de rede for local, o programa deve enviar um ARP request para cada endereço IP do endereço de rede, aguardar o ARP reply e imprimir que a máquina está ativa, apresentando o seu endereço MAC. Se o endereço de rede não for local, o programa deve enviar um ECHO Request para cada endereço IP pertencente ao endereço de rede, aguardar o ECHO Reply e imprimir que a máquina está ativa, apresentando o RTT até a máquina. Para cada máquina ativa encontrada, o programa deve verificar se as portas, indicadas na entrada, estão ativas na máquina usando os protocolos TCP e UDP.

Referências

Python libraries
https://docs.python.org/3/library/socket.html
https://docs.python.org/3/library/struct.html
TCP/IP
https://www.sans.org/security-resources/tcpip.pdf
