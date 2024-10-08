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

# copy build script and sources in image
COPY build_kernel.sh /build_kernel.sh
COPY linux-mainline-sev-src /src
RUN chown -R builder:wheel /src

# add builder to doas
RUN echo "permit nopass :wheel" >> /etc/doas.conf

USER builder

# create signing key
RUN abuild-keygen -a -i -n

WORKDIR /src

# run the build!
ENTRYPOINT ["sh", "/build_kernel.sh"]
