FROM ubuntu:22.04
# Update
RUN apt update --fix-missing && \
    apt install -y socat && \
    # mine
    apt install -y file curl binutils python3 gdb && \
    rm -rf /var/lib/apt/lists/*
# Create ctf-user
RUN groupadd -r ctf && useradd -r -g ctf ctf
ADD challenge/ /home/ctf/
RUN chmod 444 /home/ctf/flag.txt
RUN chmod 777 /home/ctf/server
RUN chown ctf:ctf /home/ctf # mine
USER ctf
WORKDIR /home/ctf
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)" # mine
# ENV TESTING_MODE=ON
# ENV PRIV_MODE=ON
EXPOSE 1337
ENTRYPOINT ["./server"]
#ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:./server"]
