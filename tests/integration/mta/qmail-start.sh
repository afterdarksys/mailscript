#!/bin/sh
set -eu
PATH=/var/qmail/bin:$PATH
export PATH
/var/qmail/bin/qmail-start ./Maildir/ cat &
exec tcpserver -R -H -u "$(id -u qmaild)" -g "$(id -g qmaild)" 0 25 /var/qmail/bin/qmail-smtpd
