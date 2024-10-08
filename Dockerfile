FROM alpine:3.20

RUN apk add alpine-sdk doas \
    &&  adduser \
    --disabled-password \
    --gecos "" \
    --ingroup "wheel" \
    --uid "1000" \
    builder

# add builder to abuild group
RUN adduser builder abuild

# copy build script in image
COPY build_kernel.sh /build_kernel.sh

# add builder to doas
RUN echo "permit nopass :wheel" >> /etc/doas.conf

USER builder

# create signing key
RUN abuild-keygen -a -i -n

# move into the sources directory, which is mounted as a volume
RUN doas mkdir /src && \
 doas chown builder /src

WORKDIR /src

# run the build!
CMD ["sh", "/build_kernel.sh"]
