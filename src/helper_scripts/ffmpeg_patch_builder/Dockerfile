# Start from the latest Ubuntu image
FROM ubuntu:latest

# Install required packages and clean up
RUN apt-get update && apt-get install -y \
   git \
   gcc \
   perl \
   make \
   nasm \
   diffutils \
   pkg-config \
   && apt-get clean \
   && rm -rf /var/lib/apt/lists/*

# Set the working directory in the Docker container
WORKDIR /ffmpeg

# Clone the FFmpeg repository
RUN git clone https://github.com/FFmpeg/FFmpeg.git .

# Build arguments
ARG COMMIT_SHA

### Patched ###

RUN git checkout $COMMIT_SHA

RUN ./configure --cc=gcc --disable-asm --enable-shared --disable-stripping
RUN make -j$(nproc)
RUN make install

RUN mkdir -p /build/patched/
RUN cp /usr/local/lib/*.so /build/patched/
RUN cp /usr/local/bin/* /build/patched/

### Original ###
RUN git checkout HEAD~1

RUN make clean

RUN ./configure --cc=gcc --disable-asm --enable-shared --disable-stripping
RUN make -j$(nproc)
RUN make install

RUN mkdir -p /build/original/
RUN cp /usr/local/lib/*.so /build/original/
RUN cp /usr/local/bin/* /build/original/
