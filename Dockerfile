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
RUN pip3 install --upgrade pip

# Install angr-dev
RUN git clone https://github.com/angr/angr-dev &&\
    cd angr-dev && \
    SETUPTOOLS_ENABLE_FEATURES='legacy-editable' ./setup.sh -e angr -b tags/v9.2.99
RUN echo 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh' >> /home/.bashrc && \
    echo 'workon angr' >> /home/.bashrc

# RUN /bin/bash -c "source /home/.bashrc"
# angr-utils: dev branch
RUN /bin/bash -c "source /home/.bashrc && \
    cd angr-dev && \
    git clone https://github.com/hwu71/angr-utils && \
    cd angr-utils && \
    git checkout 547581bbd6520fec995ec8d0954c65badfe1772d && \
    pip install -e ."

# bingraphvis: dev branch
RUN /bin/bash -c "source /home/.bashrc && \
    cd angr-dev && \
    git clone https://github.com/hwu71/bingraphvis && \
    cd bingraphvis && \
    git checkout 3d4e75d27ce53908e3dbac35f9da83f124398181 && \
    pip install -e ."

# claripy: hongwei_amp_march_2024
RUN /bin/bash -c "source /home/.bashrc && \
    cd angr-dev/claripy && \
    git fetch && \
    git checkout b7a979bfe3ac92b1238a7a160f83863b5abc9b6c"

# angr: hongwei_amp_march_2024
RUN /bin/bash -c "source /home/.bashrc && \
    cd angr-dev/angr && \
    git fetch && \
    git checkout 13d936e32ed78e62aba531030c8d020df3845c83"

# VeriBin
COPY . /veribin
RUN /bin/bash -c "source /home/.bashrc && \
    cd /veribin && pip3 install -e ."

CMD ["/bin/bash", "-c", "source /home/.bashrc && cd veribin && /bin/bash"]