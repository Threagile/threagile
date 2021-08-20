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
WORKDIR /app
COPY --from=clone /app/threagile /app
RUN go mod download
RUN go version
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o raa.so raa/raa/raa.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o dummy.so raa/dummy/dummy.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -buildmode=plugin -o demo-rule.so risks/custom/demo/demo-rule.go
RUN GOOS=linux go build -a -trimpath -ldflags="-s -w -X main.buildTimestamp=$(date '+%Y%m%d%H%M%S')" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src" -o threagile
# add the -race parameter to go build call in order to instrument with race condition detector: https://blog.golang.org/race-detector

######
## Stage 3: Make final small image
######
FROM alpine

# label used in other scripts to filter
LABEL type="threagile"
RUN apk add --update --no-cache graphviz ttf-freefont && apk add ca-certificates && apk add curl && rm -rf /var/cache/apk/*

# https://stackoverflow.com/questions/34729748/installed-go-binary-not-found-in-path-on-alpine-linux-docker
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

WORKDIR /app
COPY --from=build /app/threagile /app/threagile
COPY --from=build /app/raa.so /app/raa.so
COPY --from=build /app/dummy.so /app/dummy.so
COPY --from=build /app/demo-rule.so /app/demo-rule.so
COPY --from=build /app/LICENSE.txt /app/LICENSE.txt
COPY --from=build /app/report/template/background.pdf /app/background.pdf
COPY --from=build /app/support/openapi.yaml /app/openapi.yaml
COPY --from=build /app/support/schema.json /app/schema.json
COPY --from=build /app/support/live-templates.txt /app/live-templates.txt
COPY --from=build /app/support/render-data-asset-diagram.sh /app/render-data-asset-diagram.sh
COPY --from=build /app/support/render-data-flow-diagram.sh /app/render-data-flow-diagram.sh
COPY --from=build /app/server /app/server
COPY --from=build /app/demo/example/threagile.yaml /app/threagile-example-model.yaml
COPY --from=build /app/demo/stub/threagile.yaml /app/threagile-stub-model.yaml

RUN mkdir /data

ENV PATH=/app:$PATH
ENV GIN_MODE=release

ENTRYPOINT ["/app/threagile"]
CMD ["-help"]
