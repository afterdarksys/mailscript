#!/bin/sh
set -eu
case "$MTA" in
postfix)
  postconf -e 'myhostname = mail.test' 'mydestination = mail.test, localhost' \
    'inet_interfaces = all' 'inet_protocols = ipv4' 'maillog_file = /dev/stdout' \
    'smtpd_relay_restrictions = reject_unauth_destination' \
    'smtpd_recipient_restrictions = reject_unauth_destination' \
    'home_mailbox = Maildir/'
  exec postfix start-fg
  ;;
exim)
  cp /test-exim.conf /etc/exim4/exim4.conf
  exec exim4 -bdf -oX 25
  ;;
sendmail)
  sed -i '/^O DaemonPortOptions=/d' /etc/mail/sendmail.cf
  printf '\nO DaemonPortOptions=Port=25,Addr=0.0.0.0,Name=MTA\n' >> /etc/mail/sendmail.cf
  printf 'mail.test\n' > /etc/mail/local-host-names
  mkdir -p /run/sendmail/mta
  exec sendmail -bD -X /dev/stdout
  ;;
esac
