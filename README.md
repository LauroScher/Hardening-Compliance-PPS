

## 📝 INTRODUÇÃO

### 🎯 1. OBJETIVO DA ANÁLISE

O objetivo da análise foi simular a avaliação da segurança atual dos serviços críticos de uma empresa, identificando riscos e vulnerabilidades nas configurações e propondo ações de melhorias baseadas na ISO/IEC 27002:2022 para fortalecer a proteção e garantir as conformidades.

### 💻 2. SERVIÇOS AVALIADOS

  * Apache Web Server
  * OpenSSH Server
  * MySQL Database Server

### 📊 3. METODOLOGIA

Foi feita a comparação das configurações iniciais vs. configurações após hardening, com base nos controles da norma ISO/IEC 27002:2022, para diagnóstico e identificação de lacunas de segurança remanescentes e proposta de políticas de segurança para a mitigação dos riscos.

-----

## 🌐 APACHE WEB SERVER

### 📋 QUADRO COMPARATIVO DAS CONFIGURAÇÕES

| Controle ISO 27002:2022 | Configuração Inicial (Padrão) | Configuração Hardening | Observações |
| :---------------------- | :---------------------------- | :--------------------- | :---------- |
| 8.9 (Gestão de configuração) | `ServerRoot "/etc/httpd"` | | Linha removida por redundância, o valor é assumido como padrão pelo sistema. Controle ISO: Atendida. |
| 8.9 (Gestão de configuração) | `PidFile /var/run/httpd.pid` | | Linha removida por redundância, o Apache utiliza este valor como padrão quando não especificado. Controle ISO: Atendido. |
| 8.6 (Gestão de capacidade) \ 8.20 (Segurança de redes) | `Timeout 300` | `Timeout 60` | Reduz o tempo ocioso da conexão, minimizando riscos de ataque e reduzindo o uso desnecessário de recursos do servidor. Controle ISO: Parcialmente atendido. |
| 8.20 (Segurança de redes) | `KeepAlive On` | `KeepAlive On` | Mantém conexões ativas, quando limitada por tempo e quantidade, evita sobrecarga. Controle ISO: Parcialmente atendido. |
| 8.6 (Gestão de capacidade) \ 8.20 (Segurança de redes) | `MaxKeepAliveRequests 100` | `MaxKeepAliveRequests 50` | Limita o número de requisições por conexão, diminuindo o uso excessivo de recursos e mitigando possíveis abusos. Controle ISO: Parcialmente atendido. |
| 8.6 (Gestão de capacidade) \ 8.20 (Segurança de redes) | `KeepAliveTimeout 5` | `KeepAliveTimeout 3` | Reduz o tempo de espera por novas requisições em uma mesma conexão, diminui o risco de DDoS e uso desnecessário de conexões persistentes. Controle ISO: Parcialmente atendido. |
| 8.20 (Segurança de redes) | `Listen 80` | | Linha removida, mas sem substituição por HTTPS, pode manter a porta 80 exposta sem proteção. Controle ISO: Não Atendido. |
| 8.11 (Mascaramento de dados) \ 8.31 (Separação dos ambientes de desenvolvimento, teste e de produção) | `ServerTokens Full` | `ServerTokens Prod` | Reduz o nível de informação nos cabeçalhos das respostas HTTP, dificultando o reconhecimento da tecnologia utilizada e possíveis ataques direcionados. Controle ISO: Atendido. |
| 8.9 (Gestão de configuração) \ 8.11 (Mascaramento de dados) \ 8.12 (Prevenção de vazamento de dados) | `ServerSignature On` | `ServerSignature Off` | Remove a assinatura do Apache nas páginas de erro, evitando que informações sobre o sistema sejam usadas em ataques. Controle ISO: Atendido. |
| 8.11 (Mascaramento de dados) \ 8.12 (Prevenção de vazamento de dados) \ 8.20 (Segurança de redes) | `TraceEnable On` | `TraceEnable Off` | Impede que o servidor responda a requisições TRACE, evitando o uso desse método para extrair cookies e cabeçalhos em ataques XST (Cross-Site Tracing). Controle ISO: Atendido. |
| 8.2 (Direitos de acessos privilegiados) | `User apache` | | Nenhuma melhoria aplicada, a remoção não é recomendada sem substituição, pois o Apache pode rodar como root por padrão. Controle ISO: Não Atendido. |
| 8.2 (Direitos de acessos privilegiados) | `Group apache` | | Nenhuma melhoria foi aplicada, a remoção sem substituição explícita, enfraquece a segurança ao deixar o processo sob controle de um grupo genérico. Controle ISO: Não Atendido. |
| 8.31 (Separação dos ambientes de desenvolvimento, teste e de produção) | `DocumentRoot "/var/www/html"` | | Linha removida por redundância, o valor é assumido como padrão pelo sistema. Controle ISO: Não Atendido. |
| 8.8 (Gestão de vulnerabilidades técnicas) \ 8.11 (Mascaramento de dados) \ 8.27 (Princípios de arquitetura e engenharia de sistemas seguros) | `<Directory/>` \ `AllowOverride None` \ `Require all denied` \ `</Directory>` \ `<Directory "/var/www/html">` \ `Options -Indexes -FollowSymLinks` \ `AllowOverride None` \ `Require all granted` \ `</Directory>` | `<Directory/>` \ `AllowOverride None` \ `Require all denied` \ `</Directory>` \ `<Directory "/var/www/html">` \ `Options -Indexes -FollowSymLinks -ExecCGI` \ `AllowOverride None` \ `Require all granted` \ `</Directory>` | Aplica restrições sobre os diretórios, e impede exposição de arquivos, uso de links simbólicos e execução de scripts maliciosos. Controle ISO: Atendido. |
| 8.15 (Log) \ 8.16 (Atividades de monitoramento) | `ErrorLog "logs/error_log"` | `ErrorLog "logs/error_log"` | Diretiva mantida, garante o registro de erros e falhas do servidor para futura análise e auditoria. Controle ISO: Atendido. |
| 8.15 (Log) \ 8.16 (Atividades de monitoramento) | `LogLevel warn` | `LogLevel error` | Define o nível da severidade das mensagens que serão registradas no Log, o nível "error" registra apenas falhas críticas, reduzindo ruídos e facilitando a análise. Controle ISO: Atendido. |
| 8.15 (Log) \ 8.16 (Atividades de monitoramento) | `CustomLog "logs/access_log" combined` | `CustomLog "logs/access_log" combined` | Diretiva mantida, garantindo logs completos de acessos HTTP com formato combinado para suporte a auditoria e investigação de incidentes. Controle ISO: Atendido. |
| 8.27 (Princípios de arquitetura e engenharia de sistemas seguros) | `<IfModule dir_module>` \ `DirectoryIndex index.html` \ `</IfModule>` | | A remoção dessa diretiva elimina um comportamento previamente controlado, abrindo margem para listagens ou arquivos padrão inesperados. Controle ISO: Não Atendido. |
| 8.12 (Prevenção de vazamento de dados) \ 8.11 (Mascaramento de dados) \ 8.9 (Gestão de configuração) | | `FileETag None` | A remoção de Etags tem como objetivo aumentar a performance do servidor, além de poder ser usada para evitar vetores de ataque, dependendo de como estejam configuradas, e prevenir o vazamento de informações do servidor. Controle ISO: Atendido. |
| 8.11 (Mascaramento de dados) | | `Header always unset X-Powered-By` | Exibe no cabeçalho da resposta a tecnologia e a versão utilizada no backend. Por isso, é importante removê-lo para dificultar a identificação do ambiente e minimizar possíveis ataques. Controle ISO: Atendido. |
| 8.7 (Proteção contra Malware) | | `Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure` | Aplica proteções aos cookies enviados pelo servidor, tornando-os inacessíveis via JavaScript (HttpOnly) e exigindo conexão segura (Secure). Isso ajuda a mitigar ataques como XSS (Cross-site Scripting) e o roubo de cookies em conexões não criptografadas. Controle ISO: Atendida. |

### 🚨 LACUNAS, RISCOS E POLÍTICAS

  * **Lacuna**: Apesar da remoção explícita da diretiva `Listen 80`, a ausência de uma substituição ou da configuração de redirecionamento para HTTPS pode fazer com que a porta 80 permaneça ativa de forma implícita, o que pode deixar a comunicação insegura.

      * **Risco**: Sem a configuração de um certificado, a comunicação será em texto claro, sem o uso de criptografia.
      * **Política**: Configuração de porta e certificado para utilizar HTTPS.
      * **Controle ISO**: 8.24 Uso de criptografia

  * **Lacuna**: A ausência do `User` pode fazer com que o Apache seja executado com permissões elevadas, como o usuário `root`.

      * **Risco**: Invasor poderá ter privilégios elevados caso consiga invadir o servidor.
      * **Política**: Configurar usuário com permissões mínimas para executar a aplicação.
      * **Controle ISO**: 8.18 Uso de programas utilitários privilegiados

  * **Lacuna**: Se o grupo não for definido, o Apache pode ser executado com um grupo padrão que possua permissões mais amplas.

      * **Risco**: Invasor poderá ter privilégios elevados caso consiga invadir o servidor.
      * **Política**: Configurar grupo com permissões mínimas para executar a aplicação.
      * **Controle ISO**: 8.18 Uso de programas utilitários privilegiados

  * **Lacuna**: A ausência da configuração de `<IfModule dir_module>` pode levar à listagem de diretório.

      * **Risco**: Listagem de diretório pode levar um invasor a descobrir arquivos dentro do servidor e como está configurado.
      * **Política**: Impedir a listagem de diretório com configuração adequada.
      * **Controle ISO**: 8.9 Gestão de configuração

-----

## 🔑 OPENSSH SERVER

### 📋 QUADRO COMPARATIVO DAS CONFIGURAÇÕES

| Controle ISO 27002:2022 | Configuração Inicial (Padrão) | Configuração Hardening | Observações |
| :---------------------- | :---------------------------- | :--------------------- | :---------- |
| | `Port 22` | `Port 22` | Uso de porta padrão. Controle ISO: Não Atendido. |
| 8.9 (Gestão de configuração) | `Protocol 2` | `Protocol 2` | Protocolo mais seguro usado pelo SSH. Controle ISO: Atendido. |
| 5.15 (Controle de acesso) \ 8.2 (Direitos de acessos privilegiados) | `PermitRootLogin yes` | `PermitRootLogin no` | "restrições ao acesso privilegiado". Controle ISO: Atendido. |
| 5.17 (Informação de autenticação) | `PasswordAuthentication yes` | `PasswordAuthentication no` | Ao desativar a autenticação com senha, força o uso de chaves públicas. Aumentando a segurança ao remover métodos mais fracos de autenticação. Controle ISO: Parcialmente atendido. |
| 5.17 (Informação de autenticação) | `PermitEmptyPasswords yes` | `PermitEmptyPasswords no` | Mitigado ao não permitir acesso com senha vazia. Controle ISO: Atendido. |
| 5.17 (Informações de autenticação) \ 8.8 (Gestão de vulnerabilidades técnicas) | `ChallengeResponseAuthentication yes` | `ChallengeResponseAuthentication no` | Aumenta a segurança ao remover métodos mais fracos de autenticação, mas pode introduzir riscos operacionais, como perda de acesso. Controle ISO: Parcialmente atendido. |
| 5.17 (Informações de autenticação) \ 8.8 (Gestão de vulnerabilidades técnicas) | `UsePAM yes` | `UsePAM yes` | Ao desabilitar o Challenge Response Authentication, não é mais necessário o UsePAM, porém é um método seguro de autenticação. O ideal é ser utilizado em conjunto, nesse formato está ativo, mas não sendo utilizado corretamente. Controle ISO: Parcialmente atendido. |
| 8.9 (Gestão de configuração) | `X11Forwarding yes` | `X11Forwarding no` | Desabilitado a permissão de execução gráfica do servidor, diminuindo a superfície de ataque, pois não é um serviço necessário. Controle ISO: Atendida. |
| 8.21 (Segurança dos serviços de rede) | | `AllowTcpForwarding no` | "Parâmetros técnicos necessários para a conexão segura com os serviços de rede". Controle ISO: Atendido. |
| 8.5 (Autenticação segura) | | `MaxAuthTries 3` | Restrição de tentativas de conexão falha, importante para mitigar ataques de força bruta. Controle ISO: Atendido. |
| 8.9 (Gestão de configuração) | `X11DisplayOffset 10` | | Como o X11Forwarding foi desativado, o X11DisplayOffset 10 não se faz necessário. Desabilitando recursos desnecessários. Controle ISO: Atendido. |
| | `PrintMotd no` | | Exibe conteúdo de `/etc/motd` após o login SSH, pode ser usado para reforçar políticas de segurança. |
| 8.5 (Autenticação segura) | `ClientAliveInterval 0` | `ClientAliveInterval 300` | Restrição do tempo de duração de sessão. Controle ISO: Atendido. |
| 8.21 (Segurança dos serviços de rede) \ 8.5 (Autenticação segura) | `ClientAliveCountMax 3` | `ClientAliveCountMax 2` | Restrição do tempo de duração de sessão. Controle ISO: Atendido. |
| 8.5 (Autenticação segura) | | `LoginGraceTime 30` | Restrição do tempo de duração de sessão. Controle ISO: Atendido. |
| 8.9 (Gestão de configuração) \ 8.8 (Gestão de vulnerabilidades técnicas) | | `PermitUserEnvironment no` | Restringe o acesso de usuários a ambiente de personalização do SSH. Controle ISO: Atendida. |
| 8.9 (Gestão de configuração) | `Subsystem sftp /usr/lib/openssh/sftp-server` | `Subsystem sftp /usr/lib/openssh/sftp-server` | Garante transferência segura de arquivos em ambas configurações. Controle ISO: Atendido. |
| | | `Banner /etc/issue.net` | Banner tem por finalidade ser informativo, porém pode ser utilizado para apresentar as políticas e reforçar políticas de segurança. |

### 🚨 LACUNAS, RISCOS E POLÍTICAS

  * **Lacuna**: Uso da porta padrão (22).

      * **Risco**: Alvo fácil para scanners automatizados e ataques de força bruta.
      * **Política**: Definir uma porta customizada diminui o risco de ataques de força bruta.
      * **Controle ISO**: 8.5 Autenticação segura, 8.9 Gestão de configuração

  * **Lacuna**: Desabilitar o `PasswordAuthentication` e o `ChallengeResponseAuthentication` aumenta a segurança por remover métodos mais fracos de autenticação, mas pode introduzir riscos operacionais, como perda de acesso. O `UsePAM` não está sendo útil na configuração, podendo permitir mecanismos de autenticação não desejados se mal configurado.

      * **Risco**: Bypass da autenticação baseada em chave se o PAM estiver configurado de forma insegura.
      * **Política**: Desabilitar o `UsePAM` ou habilitar o `ChallengeResponseAuthentication`.
      * **Controle ISO**: 8.9 Gestão de configuração.

  * **Lacuna**: Ausência de Autenticação de Múltiplos Fatores (MFA/2FA). Apenas a chave SSH é usada (`PasswordAuthentication no`).

      * **Risco**: Comprometimento da chave SSH concede acesso direto.
      * **Política**: Se o acesso via SSH desse servidor for exposto na internet, o MFA se faz importante para evitar ataques de força bruta.
      * **Controle ISO**: 5.17 Informações de autenticação

  * **Lacuna**: Não está configurado as restrições de acesso por usuários ou grupos.

      * **Risco**: Acesso não autorizado ou indevido tanto interno quanto externo, maior superfície de ataque por não ter especificado quais usuários estão autorizados.
      * **Política**: Limitar usuários ou grupos liberando apenas os especificados na configuração. Ex: `AllowUsers nome.sobrenome`, `AllowGroups nomedogrupo`.
      * **Controle ISO**: 5.15 Controle de acesso

  * **Lacuna**: Não está configurado o registro de logs do servidor.

      * **Risco**: Comprometimento da rastreabilidade das atividades no servidor, dificultando a detecção de tentativas de acesso e possíveis incidentes de segurança.
      * **Política**: Configurar registro de logs do servidor, como `Loglevel VERBOSE`, para fins de auditorias.
      * **Controle ISO**: 8.15 Log

-----

## 🗄️ MYSQL DATABASE SERVER

### 📋 QUADRO COMPARATIVO DAS CONFIGURAÇÕES

| Controle ISO 27002:2022 | Configuração Inicial (Padrão) | Configuração Hardening | Observações |
| :---------------------- | :---------------------------- | :--------------------- | :---------- |
| 8.2 (Direitos de acessos privilegiados) 8.27 (Princípios de arquitetura e engenharia de sistemas seguros) | `user=mysql` | `user=mysql` | Diretiva mantida, configuração de segurança usada para definir ao usuário privilégios mínimos sem funções de administrador. Controles ISO: Atendidos. |
| 8.20 (Segurança de redes) | `port=3306` | `port=3306` | Diretiva mantida, configuração de segurança para definir a porta padrão usada para conexões SQL. Controle ISO: Atendido. |
| 5.15 (Controle de acesso) \ 8.20 (Segurança de redes) | `bind-address=0.0.0.0` | `bind-address=127.0.0.1` | Alteração realizada para evitar que o MySQL use conexões em todas as interfaces de rede. Melhoria aplicada para limitar as conexões apenas para o local host. Controles ISO: Atendidos. |
| 8.3 (Restrição de acesso à informação) | `datadir=/var/lib/mysql` | `datadir=/var/lib/mysql` | Diretiva mantida, configuração que define qual diretório ficam armazenado os dados do MySQL. Essa configuração sozinha não garante a segurança dos ativos, é necessário implementar outras políticas de seguranças que atendam os controles de acesso. Controle ISO: Parcialmente atendido. |
| 8.21 (Segurança dos serviços de rede) | `socket=/var/lib/mysql/mysql.sock` | `socket=/var/lib/mysql/mysql.sock` | Diretiva mantida, configuração que define o local do arquivo de socket Unix usado para conexões locais. Uma conexão via socket Unix não expõe o tráfego na rede e limita as conexões apenas para o próprio host. Controle ISO: Atendido. |
| 5.15 (Controle de acesso) \ 8.27 (Princípios de arquitetura e engenharia de sistemas seguros) | `symbolic-links=0` | `symbolic-links=0` | Diretiva mantida, configuração de segurança responsável por desabilitar links simbólicos para prevenir atalhos de acesso a arquivos sensíveis do sistema. Controles ISO: Atendidos. |
| 5.15 (Controle de acesso) \ 8.20 (Segurança de redes) | `skip-symbolic-links` | `skip-symbolic-links` | Diretiva mantida, evita que o servidor da SQL carregue diretórios ou dados por meio de links simbólicos. Controles ISO: Atendidos. |
| 8.15 (Log) \ 8.16 (Atividades de monitoramento) | `log-error=/var/log/mysqld.log` | `log-error=/var/log/mysqld.log` | Diretiva mantida, configuração de segurança implementada para registrar erros operacionais do MySQL, como falhas de autenticação ou corrupção de dados. Aumenta a capacidade de auditoria e resposta a incidentes. |
| 8.27 (Princípios de arquitetura e engenharia de sistemas seguros) | `pid-file=/var/run/mysqld/mysqld.pid` | `pid-file=/var/run/mysqld/mysqld.pid` | Diretiva mantida, configuração de segurança implementada para armazenar o identificador do processo do MySQL. Facilita o gerenciamento do serviço e evita conflitos de execução ou inicializações simultâneas. Controles ISO: Atendidos. |
| 5.15 (Controle de acesso) \ 8.8 (Gestão de vulnerabilidades técnicas) | | `local-infile=0` | Configuração de segurança implementada para desativar o comando "Local-infile" responsável por gerenciar arquivos, como importar e exportar. Controles ISO: Atendidos. |
| 8.20 (Segurança de redes) \ 8.30 (Restrição de acesso à informação) | | `skip-name-resolve` | Configuração de segurança implementada para restringir consultas por conexões DNS, forçando o MySQL a realizar comunicações via IPs. Aplicação aumenta a velocidade das conexões e reduz ataques via spoofing. Controles ISO: Atendidos. |
| 8.3 (Restrição de acesso à informação) \ 8.2 (Direitos de acessos privilegiados) | | `skip-show-database` | Configuração de segurança implementada para privar usuários, sem privilégios, a visualizarem a lista dos bancos de dados presente no MySQL. Evita que informações sejam visualizadas por agente mal intencionado. Controles ISO: Atendidos. |
| 5.15 (Controle de acesso) \ 8.3 (Restrição de acesso à informação) \ 8.2 (Direitos de acessos privilegiados) | | `secure-file-priv="/var/lib/mysql-files"` | Configuração de segurança implementada para restringir o acesso ao diretório responsável por importar e exportar dados. Garante a segurança de possíveis adulterações indevidas. Controles ISO: Parcialmente atendidas. |
| 8.2 (Direitos de acessos privilegiados) \ 5.17 (Autenticação de usuário) \ 5.18 (Gestão de informações de autenticação) | `default_authentication_plugin=mysql_native_password` | `default_authentication_plugin=mysql_native_password` | Diretiva mantida, define o plug-in de autenticação utilizado, garantindo que os usuários sejam validados com senha no padrão definido pela política de segurança. Controles ISO: Atendidos. |
| 5.14 (Transferência de Informações) \ 8.23 (Filtragem web) | | `require_secure_transport=ON` | Configuração de segurança implementada para realizar apenas conexões web criptografadas via SSL/TLS que são padrões usados no transporte de dados nos protocolos HTTPS. Controles ISO: Atendidos. |
| 5.15 (Controle de acesso) \ 8.20 (Segurança de redes) | | `skip-symbolic-links` | Configuração de segurança implementada de forma repetida, não agregando em nenhuma função adicional ao sistema. Controles ISO: Não Atendidos. |
| 5.17 (Autenticação secreta) e \ 5.15 (Controle de acesso) | `validate_password.policy=STRONG` | `validate_password.policy=STRONG` | Configuração de segurança implementada para definir um padrão de complexidade para senhas, como comprimento mínimo e combinação de letras, números e caracteres especiais. Dificulta os ataques de força bruta. Controles ISO: Atendidos. |
| 5.17 (Autenticação secreta) e \ 5.15 (Controle de acesso) | `validate_password.length=12` | `validate_password.length=12` | Configuração de segurança implementada para complementar a configuração "STRONG" e definir um mínimo de 12 caracteres para criação de senhas. Também dificulta ataques de força bruta. Controles ISO: Atendidos. |



### 🚨 LACUNAS, RISCOS E POLÍTICAS

  * **Lacuna**: Na linha de configuração `bind-address=127.0.0.1`, priva os acessos remotos e impede qualquer conexão externa.

      * **Risco**: Não há monitoramento remoto, impactando na disponibilidade e no serviço de aplicações distribuídas que estão hospedadas em outros servidores.
      * **Política**: Acesso remoto seguros para monitoramento e manutenções.
      * **Controle ISO**: 6.7 Trabalho remoto, 8.3 Restrição de acesso à informação, 8.9 Gestão de configuração.

  * **Lacuna**: Na linha de configuração `log-error=/var/log/mysqld.log`. Logs são registrados apenas localmente.

      * **Risco**: Risco de perda de evidências por falta de backups e armazenamentos externos.
      * **Política**: Uso de serviços remoto para redirecionamento dos logs locais.
      * **Controle ISO**: 5.23 Segurança da informação para uso de serviços em nuvem, 5.33 Proteção de registros, 8.13 Backup das informações.

  * **Lacuna**: Na linha de configuração `secure-file-priv="/var/lib/mysql-files"`, priva o acesso ao diretório "/var/lib/mysql-files".

      * **Risco**: Apesar de privar os acessos ao diretório, não há controle de privilégios. Risco de privilégios indevidos podem ser concedidos.
      * **Política**: Definir privilégios mínimos de permissões por tipos de usuários no MySql e usar criptografia para dados sensíveis armazenados nesse diretório.
      * **Controle ISO**: 5.17 Informação de autenticação, 5.3 Segregação de funções, 8.2 Direitos de acessos privilegiado, 8.24 Uso de criptografia.

-----

## ✅ CONCLUSÃO

A avaliação de segurança dos serviços Apache, OpenSSH e MySQL demonstrou que suas configurações iniciais apresentavam riscos significativos para a segurança, como diretivas permissivas e ausência de restrições de acesso.

A implementação de medidas de hardening resultou em melhorias na segurança de todos os três serviços, alinhando-os mais proximamente às boas práticas de segurança da informação com base nos controles da ISO/IEC 27002:2022.

No entanto, ainda existem pontos de atenção, que podem ser ajustados através das sugestões fornecidas no relatório. Para garantir a manutenção e a eficácia contínua dos controles de segurança, é fundamental estabelecer uma rotina de revisão periódica das configurações, assegurando a conformidade com os controles relevantes da norma utilizada.

-----



