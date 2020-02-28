FROM alpine:3.11


RUN apk update
RUN apk add \
      build-base \
      gdb \
      python3 \
      python3-dev \
      py3-virtualenv

RUN python3 -m pip install pipx && \
    pipx install gdbgui

EXPOSE 5000

CMD /root/.local/bin/gdbgui --host 0.0.0.0 --no-browser
