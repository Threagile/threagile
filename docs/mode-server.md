# Server mode

Threagile may run as a server on your local machine. To do it simply run command `server` and
by default (unless you changed server values in [config](./config.md) or [flags](./flags.md)) web server will be accessible from localhost:8080

The server is using [gin](https://github.com/gin-gonic/gin) to serve HTTP connection and have few limitations:

- do not support [includes](./includes.md)
- single threaded - because of dependency on running graphviz as a process

## Edit feature

In server mode you can also go and edit model, run analysis on it in UI. The feature is under development and that's only very first iteration is ready.
But most viable product here would be adding an ability to do changes to your model via UI.

Here’s a quick demonstration of the project:

<video width="600" controls>
  <source src="./edit-model.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

Or download and play it locally:

[Download Video](./edit-model.mp4)

Most important note that the model is fully in the memory of the browser and to store it somewhere you need to export it to your hard drive.

The UI is fully based on the [schema.json](../support/schema.json).

There are a lot of improvements for the feature such as:

1. Allow adding custom risk tracking (currently it's broken).
2. Improve changing technical assets (remember all of dragging around).
3. Add question mark with explanation for each field.
