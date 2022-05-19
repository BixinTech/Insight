### How to compile & load

```sh
$ npm install
either
$ frida -U gadget --no-pause -l _agent.js
or
$ frida -H {ip} gadget --no-pause -l _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
