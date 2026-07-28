FROM php@sha256:c5aa11a8d2dfe5c895d67bd602118362d017e724b7ec3e5b6e296dd5c92110c4

# Install build dependencies
RUN apt update --fix-missing && apt install -y \
    file curl binutils procps build-essential \
    libssl-dev zlib1g-dev libffi-dev libsqlite3-dev wget

# Build and install Python 3.10
RUN wget https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tgz && \
    tar -xf Python-3.10.13.tgz && \
    cd Python-3.10.13 && \
    ./configure --enable-optimizations && \
    make -j$(nproc) && \
    make altinstall && \
    cd .. && rm -rf Python-3.10.13*

RUN ln -s /usr/local/bin/python3.10 /usr/local/bin/python && \
    ln -s /usr/local/bin/python3.10 /usr/local/bin/python3

# 3. Build GDB linked with Python 3.10
RUN apt install -y libexpat1-dev libgmp-dev
RUN wget https://ftp.gnu.org/gnu/gdb/gdb-13.2.tar.gz && \
    tar -xf gdb-13.2.tar.gz && \
    cd gdb-13.2 && \
    ./configure --with-python=/usr/local/bin/python3.10 && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf gdb-13.2*

RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

RUN useradd --user-group --no-log-init ctf
COPY challenge/php_logger.so /php_logger.so
COPY challenge /web
RUN mv /web/flag.txt /
WORKDIR /web
EXPOSE 1337
USER ctf
CMD ["/web/start.sh"]
