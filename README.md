# SilverBullet Cloudflare Workers
This is a Cloudflare Workers implementation of SilverBullet, an open source **personal productivity platform** built on Markdown. It's designed to run on Cloudflare's edge network, providing fast access from anywhere in the world.

## Features
* **Edge Computing**: Runs on Cloudflare's global network for low-latency access
* **R2 Storage**: Uses Cloudflare R2 for data storage
* **Markdown Support**: Full Markdown editing and preview capabilities
* **PWA Support**: Works as a Progressive Web App
* **Offline Capable**: Syncs content when back online
* **Self-hosted**: You own your data, stored in your R2 bucket

## Development

### Prerequisites
- Rust and Cargo
- Deno
- Wrangler CLI (`npm install -g wrangler`)
- jq
- Cloudflare account with R2 enabled

### Setup
1. Clone this repository
2. Create an R2 bucket in your Cloudflare account

### Building and Deployment
The deployment process consists of several steps:

1. Build the asset bundles:
```shell
deno task build
```

1. Setup Wrangler Files
```shell
cp wrangler.jsonc.template wrangler.jsonc
```

edit `wrangler.jsonc` with your own domain and bucket name by replacing `SB_CF_UNIQUE_WORKER_NAME`, `SB_CF_UNIQUE_DOMAIN_NAME` and `SB_CF_UNIQUE_BUCKET_NAME` with your own values. (like `silverbullet`, `example.com` and `silverbullet`)

1. Upload the asset bundles to R2:
```shell
wrangler r2 object put {fill_your_bucket_name}/dist/client_asset_bundle.json --file dist/client_asset_bundle.json --remote
wrangler r2 object put {fill_your_bucket_name}/dist/plug_asset_bundle.json --file dist/plug_asset_bundle.json --remote
```

1. Generate asset bundle indices:
```shell
jq 'map_values({mtime: .mtime, content_type: (.data | split(";")[0] | split(":")[1])})' dist/client_asset_bundle.json >dist/client_asset_index.json
jq 'map_values({mtime: .mtime, content_type: (.data | split(";")[0] | split(":")[1])})' dist/plug_asset_bundle.json >dist/plug_asset_index.json
```

1. Deploy the worker:
```shell
wrangler deploy
```

## License
MIT License

---

# SilverBullet
SilverBullet is an open source **personal productivity platform** built on Markdown, turbo charged with the scripting power of Lua. You self host it on your server, access it via any modern browser on any device (desktop, laptop, mobile). Since SilverBullet is built as a Local First PWA, it is fully offline capable. Temporarily don't have network access? No problem, SilverBullet will sync your content when you get back online.

You may start your SilverBullet journey by simply thinking of it as a note taking app. Because, well, it is. You write notes in Markdown and get Live Preview. It looks WYSIWYG while still easily accessing the markdown that lies underneath. You can create Links to other pages, via the `[[other page]]` syntax. As you navigate your Space (that's what we call a SilverBullet instance) by clicking these links, you will see Linked Mentions to get a feel of how your pages are inter-linked.

Then you learn that in SilverBullet, you can embed Space Lua (SilverBullet's Lua dialect) right into your pages, using the special `${lua expression}` syntax. You try something simple, like `${10 + 2}`. Ok, that's cool. As you learn more, you start tagging pages and adding Frontmatter. As it turns out, pages (and other things) are indexed as Objects. You realize you can query these objects like a database.

Imagine the possibilities. Before you know it — you realize you're effectively building applications in your notes app. End-User Programming, y'all. It's cool.

You may have been told there is _no such thing_ as a [silver bullet](https://en.wikipedia.org/wiki/Silver_bullet).

You were told wrong.

[![Introduction to SilverBullet](http://img.youtube.com/vi/mik1EbTshX4/0.jpg)](https://www.youtube.com/watch?v=mik1EbTshX4)

## Features
SilverBullet...
* At its core is a **note taking** application, a kind of personal wiki, storing its notes in the universal Markdown format in a folder on your server.
* Is a **web application** and therefore accessible from wherever a (modern) web browser is available.
* Is built as a Local First PWA keeping a copy of your content in your browser's local database, syncing back to the server when a network connection is available, enabling **100% offline operation**.
* Provides an enjoyable Markdown writing experience with a clean UI, rendering text using Live Preview, further **reducing visual noise** while still providing direct access to the underlying markdown syntax.
* Supports wiki-style **page linking** using the `[[page link]]` syntax. Incoming links are indexed and appear as Linked Mentions at the bottom of the pages linked to thereby providing _bi-directional linking_.
* Is optimized for **keyboard-based operation**:
  * Quickly navigate between pages using the **page switcher** (triggered with `Cmd-k` on Mac or `Ctrl-k` on Linux and Windows).
  * Run commands via their keyboard shortcuts or the **command palette** (triggered with `Cmd-/` or `Ctrl-/` on Linux and Windows).
  * Use Slash Commands to perform common text editing operations.
* Is a platform for End-User Programming through its support for Objects and Space Lua.
* Can be extended using Space Lua and Plugs, and a lot of core functionality is built that way.
* Is **self-hosted**: _you own your data_. Your space is stored as plain files in a folder on disk on your server. Back it up, sync, edit, publish, script it with any additional tools you like.
* Is free, [**open source**, MIT licensed](https://github.com/silverbulletmd/silverbullet) software.

## Installing SilverBullet
Check out the [instructions](https://silverbullet.md/Install).

## Developing SilverBullet

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/silverbulletmd/silverbullet)

SilverBullet is written in [TypeScript](https://www.typescriptlang.org/) and
built on top of the excellent [CodeMirror 6](https://codemirror.net/) editor
component. Additional UI is built using [Preact](https://preactjs.com).
[ESBuild]([https://parceljs.org/](https://esbuild.github.io)) is used to build both the front-end and
back-end bundles. The server backend runs as a HTTP server on Deno using and is written using [Hono](https://hono.dev).

To prepare the initial web and plug build run:

```shell
deno task build
```

To symlink `silverbullet` to your locally checked-out version, run:

```shell
deno task install
```

You can then run the server in "watch mode" (automatically restarting when you
change source files) with:

```shell
deno task watch-server <PATH-TO-YOUR-SPACE>
```

After this initial build, it's convenient to run three commands in parallel (in
separate terminals):

```shell
deno task watch-web
deno task watch-server <PATH-TO-YOUR-SPACE>
deno task watch-plugs
```

To typecheck the entire codebase (recommended before submitting PR):
```shell
deno task check
```