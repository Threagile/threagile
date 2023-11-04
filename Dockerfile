######
## Stage 1: Clone the Git repository
######
FROM alpine/git as clone
WORKDIR /app
RUN git clone https://github.com/threagile/threagile.git




######
## Stage 2: Build application with Go's build tools
######
FROM golang as build
ENV GO111MODULE=on
# https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
#ENV CGO_ENABLED=0 # cannot be set as otherwise plugins don't run
WORKDIR /app
COPY --from=clone /app/threagile /app
RUN go version
RUN go test ./...
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -buildmode=plugin -o raa.so raa/raa/raa.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -buildmode=plugin -o dummy.so raa/dummy/dummy.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -buildmode=plugin -o demo-rule.so risks/custom/demo/demo-rule.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -o threagile
# add the -race parameter to go build call in order to instrument with race condition detector: https://blog.golang.org/race-detector
# NOTE: copy files with final name to send to final build
RUN cp /app/demo/example/threagile.yaml /app/demo/example/threagile-example-model.yaml && \
    cp /app/demo/stub/threagile.yaml /app/demo/stub/threagile-stub-model.yaml

######
## Stage 3: Copy needed files into desired folder structure
######

FROM scratch AS files

COPY --from=build --chown=1000:1000 \
    /app/threagile \
    /app/raa.so \
    /app/dummy.so \
    /app/demo-rule.so \
    /app/LICENSE.txt \
    /app/report/template/background.pdf \
    /app/support/openapi.yaml \
    /app/support/schema.json \
    /app/support/live-templates.txt \
    /app/support/render-data-asset-diagram.sh \
    /app/support/render-data-flow-diagram.sh \
    /app/demo/example/threagile-example-model.yaml \
    /app/demo/stub/threagile-stub-model.yaml \
    \
    /app/

COPY --from=build --chown=1000:1000 /app/server /app/server

######
## Stage 4: Make final small image
######
FROM alpine

# label used in other scripts to filter
LABEL type="threagile"

# add certificates
RUN apk add --update --no-cache ca-certificates \
# add graphviz, fonts \
    graphviz ttf-freefont \
# https://stackoverflow.com/questions/66963068/docker-alpine-executable-binary-not-found-even-if-in-path \
    libc6-compat && \
# https://stackoverflow.com/questions/34729748/installed-go-binary-not-found-in-path-on-alpine-linux-docker
# RUN mkdir -p /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
# clean apk cache
    rm -rf /var/cache/apk/* && \
# create application and data directories
    mkdir -p /app /data && \
    chown -R 1000:1000 /app /data

COPY --from=files / /

USER 1000:1000
WORKDIR /app

ENV PATH=/app:$PATH \
    GIN_MODE=release

ENTRYPOINT ["/app/threagile"]
CMD ["-help"]
