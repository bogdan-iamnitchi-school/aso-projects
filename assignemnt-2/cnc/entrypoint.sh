#!/bin/bash

#TODO: Porneste serviciul pentru baza de date.
# HINT: - Pentru a porni un serviciu foloseste comanda service: https://bash.cyberciti.biz/guide/Service_command
#       - Numele serviciului pentru baza de date este mariadb.
service mariadb start

if ! test -f /app/sql-init; then
    mysql -u root < /app/db.sql
    touch /app/sql-init
fi

# TODO: Ruleaza binarul compilat in Dockerfile din fisierele .go.
./cnc