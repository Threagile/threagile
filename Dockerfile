

######
## Stage 1: Clone the Git repository
######
FROM alpine/git AS clone
WORKDIR /app

RUN git clone https://github.com/threagile/threagile.git




######
## Stage 2: Build application with Go's build tools
######
FROM golang AS build
WORKDIR /app

ENV GO111MODULE=on

# https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
#ENV CGO_ENABLED=0 # cannot be set as otherwise plugins don't run
COPY --from=clone /app/threagile /app

RUN go version
RUN go test ./...
RUN GOOS=linux go build -ldflags="-X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -o risk_demo_rule cmd/risk_demo/main.go
RUN GOOS=linux go build -ldflags="-X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -o threagile
# add the -race parameter to go build call in order to instrument with race condition detector: https://blog.golang.org/race-detector
# NOTE: copy files with final name to send to final build
RUN cp /app/demo/example/threagile.yaml /app/demo/example/threagile-example-model.yaml
RUN cp /app/demo/stub/threagile.yaml /app/demo/stub/threagile-stub-model.yaml




######
## Stage 3: Make final small image
######
FROM alpine AS deploy
WORKDIR /app

# label used in other scripts to filter
LABEL type="threagile"

# add certificates
RUN apk add --update --no-cache ca-certificates
# add graphviz, fonts
RUN apk add --update --no-cache graphviz ttf-freefont
# https://stackoverflow.com/questions/66963068/docker-alpine-executable-binary-not-found-even-if-in-path
RUN apk add libc6-compat
# https://stackoverflow.com/questions/34729748/installed-go-binary-not-found-in-path-on-alpine-linux-docker
# RUN mkdir -p /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
# clean apk cache
RUN rm -rf /var/cache/apk/*

RUN mkdir -p /app /data
RUN chown -R 1000:1000 /app /data

COPY --from=build --chown=1000:1000 /app/threagile /app/
COPY --from=build --chown=1000:1000 /app/risk_demo_rule /app/
COPY --from=build --chown=1000:1000 /app/LICENSE.txt /app/
COPY --from=build --chown=1000:1000 /app/report/template/background.pdf /app/
COPY --from=build --chown=1000:1000 /app/support/openapi.yaml /app/
COPY --from=build --chown=1000:1000 /app/support/schema.json /app/
COPY --from=build --chown=1000:1000 /app/support/live-templates.txt /app/
COPY --from=build --chown=1000:1000 /app/demo/example/threagile-example-model.yaml /app/
COPY --from=build --chown=1000:1000 /app/demo/stub/threagile-stub-model.yaml /app/
COPY --from=build --chown=1000:1000 /app/server /app/server

USER 1000:1000

ENV PATH=/app:$PATH GIN_MODE=release

ENTRYPOINT ["/app/threagile"]
CMD ["help"]
