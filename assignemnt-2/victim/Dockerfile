# Folosim imaginea de bază Ubuntu (cea mai recentă versiune).
FROM ubuntu:latest

# Instalăm pachetele necesare pentru telnet (telnetd, openbsd-inetd) și tcpdump (pentru analiza pachetelor rețelei).
RUN apt update && apt install -y telnetd openbsd-inetd tcpdump

# Creăm un utilizator numit 'admin' cu permisiuni de root (sudouser).
# Folosim openssl pentru a crea o parolă criptată pentru utilizator. Parola este 'admin'.
RUN useradd -rm -d /home/admin -s /bin/bash -g root -G sudo -u 1001 admin -p "$(openssl passwd -1 admin)"

# Adăugăm linia necesară în fișierul /etc/inetd.conf pentru a configura serviciul Telnet să ruleze la cerere.
RUN echo "telnet stream tcp nowait root /usr/sbin/telnetd telnetd" >> /etc/inetd.conf

# Expunem portul 23, care este folosit de Telnet.
EXPOSE 23

# Pornim serviciul 'inetd' pentru a permite conexiuni Telnet și utilizăm comanda 'service' pentru a verifica serviciile.
# Apoi folosim tcpdump pentru a asculta pachetele de rețea și a le analiza.
# 'sleep infinity' este folosit pentru a menține containerul activ indefinit.
ENTRYPOINT /usr/sbin/inetd && service --status-all && tcpdump -i any -n ip && sleep infinity
