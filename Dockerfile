FROM ubuntu:focal
ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386


RUN apt-get update && apt-get -o APT::Immediate-Configure=0 install -y \
    virtualenvwrapper python3-dev python3-pip build-essential libxml2-dev \
    libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap \
    debian-archive-keyring libglib2.0-dev libpixman-1-dev qtdeclarative5-dev \
    binutils-multiarch nasm libc6:i386 libgcc1:i386 libstdc++6:i386 \
    libtinfo5:i386 zlib1g:i386 vim libssl-dev openjdk-8-jdk \
    nano \
    && rm -rf /var/lib/apt/lists/*

# symlink python3 to python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Set up angr
RUN pip3 install --upgrade pip pip wheel setuptools cffi "unicorn==2.0.1.post1" importlib_metadata

RUN git clone https://github.com/angr/archinfo.git && cd archinfo && git checkout tags/v9.2.99
RUN git clone --recursive https://github.com/angr/pyvex.git && cd pyvex && git checkout tags/v9.2.99
RUN git clone https://github.com/angr/cle.git && cd cle && git checkout tags/v9.2.99
RUN git clone https://github.com/angr/claripy.git && cd claripy && git checkout tags/v9.2.99
RUN git clone https://github.com/angr/ailment.git && cd ailment && git checkout tags/v9.2.99
RUN git clone https://github.com/angr/angr.git && cd angr && git checkout tags/v9.2.99

RUN pip install -e ./archinfo --config-settings editable_mode=compat
RUN pip install -e ./pyvex --config-settings editable_mode=compat
RUN pip install -e ./cle --config-settings editable_mode=compat
RUN pip install -e ./claripy --config-settings editable_mode=compat
RUN pip install -e ./ailment --config-settings editable_mode=compat
RUN pip install -e ./angr --config-settings editable_mode=compat


# angr-utils: dev branch
RUN git clone https://github.com/hwu71/angr-utils && \
    cd angr-utils && \
    git checkout 547581bbd6520fec995ec8d0954c65badfe1772d && \
    pip install -e . --config-settings editable_mode=compat

# bingraphvis: dev branch
RUN git clone https://github.com/hwu71/bingraphvis && \
    cd bingraphvis && \
    git checkout 3d4e75d27ce53908e3dbac35f9da83f124398181 && \
    pip install -e . --config-settings editable_mode=compat

# claripy: hongwei_amp_march_2024
RUN cd claripy && \
    git fetch && \
    git checkout b7a979bfe3ac92b1238a7a160f83863b5abc9b6c

# angr: hongwei_amp_march_2024
RUN cd angr && \
    git fetch && \
    git checkout 13d936e32ed78e62aba531030c8d020df3845c83

# VeriBin
COPY . /veribin
RUN cd /veribin && pip install -e . --config-settings editable_mode=compat

CMD ["/bin/bash", "-c", "cd veribin && /bin/bash"]