# Server mode

Threagile may run as a server on your local machine. To do it simply run command `server` and
by default (unless you changed server values in [config](./config.md) or [flags](./flags.md)) web server will be accessible from localhost:8080

The server is using [gin](https://github.com/gin-gonic/gin) to serve HTTP connection and have few limitations:

- do not support [includes](./includes.md)
- single threaded - because of dependency on running graphviz as a process
