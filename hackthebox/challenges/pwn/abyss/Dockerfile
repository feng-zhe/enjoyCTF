FROM ubuntu:latest

RUN apt-get update && apt-get install -y socat

WORKDIR /app
COPY challenge/abyss .
COPY challenge/flag.txt .
RUN echo $(tr -dc A-Za-z0-9 </dev/urandom | head -c 15):$(tr -dc A-Za-z0-9 </dev/urandom | head -c 15) > .creds

# mine
RUN apt-get install -y file curl binutils python3 gdb
RUN rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
USER ctf
# mine
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"


EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/abyss"]
