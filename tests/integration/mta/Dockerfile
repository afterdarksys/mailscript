FROM debian:bookworm-slim
ARG MTA
ENV MTA=${MTA}
RUN apt-get update -qq && \
    case "$MTA" in \
      postfix) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix ;; \
      exim) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq exim4-daemon-light ;; \
      sendmail) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sendmail-bin sendmail-cf procmail ;; \
      *) exit 1 ;; \
    esac
RUN if [ "$MTA" = sendmail ]; then DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y -qq sensible-mda; fi
RUN useradd -m -s /bin/sh probe
COPY start.sh /start.sh
COPY exim.conf /test-exim.conf
ENTRYPOINT ["/bin/sh", "/start.sh"]
