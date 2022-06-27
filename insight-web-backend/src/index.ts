import express from "express";
import cors from "cors";
import { ChildProcessWithoutNullStreams, spawn } from "child_process";
import WebSocket, { WebSocketServer } from "ws";

class ResponseCode {
  static SUCCESS: number = 8000;
  static FAILURE: number = 8001;
}

interface Response {
  code: number;
  message: string;
  data: any;
}

interface Entity {
  process: ChildProcessWithoutNullStreams;
  sessionId: string;
}

function ab2str(buf: ArrayBuffer) {
  return String.fromCharCode.apply(null, new Uint16Array(buf) as any);
}

const registry = new Map<string, Entity>();
const sockets = new Map<string, WebSocket>();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

app.get("/", (request, response) => {
  response.send("insight web backend works!");
});

app.get("/register", (request, response) => {
  function isConnected(log: string) {
    if (
      log.includes("Failed to spawn: unable to connect to remote frida-server")
    ) {
      return false;
    } else if (log.includes("Connected to ")) {
      return true;
    } else {
      return false;
    }
  }

  if (request.query.ip && request.query.SESSION_ID) {
    if (registry.has(request.query.ip as string)) {
      response.send({
        code: ResponseCode.FAILURE,
        message: "the agent has connected and been working",
      } as Response);
    } else {
      const childProcess = spawn(
        "frida",
        [
          "-H",
          `${request.query.ip}`,
          "gadget",
          "--no-pause",
          "-l",
          "_agent.js",
        ],
        { cwd: "../insight-agent" }
      );

      let output: string = "";
      childProcess.stderr.on("data", function (data) {
        console.error(data.toString());
        output += data.toString();
      });

      childProcess.stdout.on("data", function (data) {
        console.log(data.toString());
        output += data.toString();
      });

      childProcess.on("close", (code) => {
        console.log(`child process exited with code ${code}`);

        registry.delete(request.query.ip as string);
      });

      setTimeout(() => {
        if (response.writableEnded) {
        } else {
          if (isConnected(output)) {
            response.send({
              code: ResponseCode.SUCCESS,
              message: "insight agent connection established",
              data: {
                ip: request.query.ip,
                date: Date.now(),
              },
            } as Response);
            registry.set(
              request.query.ip as string,
              {
                process: childProcess,
                sessionId: request.query.SESSION_ID,
              } as Entity
            );
          } else {
            response.send({
              code: ResponseCode.FAILURE,
              message: "insight agent connection failed",
            } as Response);
          }
        }
      }, 6000);
    }
  } else {
    response.send({
      code: ResponseCode.FAILURE,
      message: "parameter ip or SESSION_ID is missing",
    } as Response);
  }
});

app.get("/connections/retrieveAll", (request, response) => {
  const array = Array.from(registry, ([name, value]) => ({ name, value }));
  response.send({
    code: ResponseCode.SUCCESS,
    data: array,
    message: "success",
  } as Response);
});

app.post("/flush", (request, response) => {
  if (request.body.IP) {
    const SESSION_ID = registry.get(request.body.IP)!!.sessionId;
    if (SESSION_ID) {
      if (sockets.has(SESSION_ID as string)) {
        const socket = sockets.get(SESSION_ID as string);
        socket?.send(
          JSON.stringify({
            signature: request.body.signature,
            stackTrace: request.body.stackTrace,
          })
        );
        response.send({
          code: ResponseCode.SUCCESS,
          message: "flush success",
        } as Response);
      } else {
        response.send({
          code: ResponseCode.FAILURE,
          message: "socket does not exists",
        } as Response);
      }
    } else {
      response.send({
        code: ResponseCode.FAILURE,
        message: "session id does not exists",
      } as Response);
    }
  } else {
    response.send({
      code: ResponseCode.FAILURE,
      message: "parameter SESSION_ID is missing",
    } as Response);
  }
});

app.listen(9080, () => {
  console.log("insight web backend listening on port 9080!");
});

const wss = new WebSocketServer({
  port: 9081,
  perMessageDeflate: {
    zlibDeflateOptions: {
      // See zlib defaults.
      chunkSize: 1024,
      memLevel: 7,
      level: 3,
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024,
    },
    // Other options settable:
    clientNoContextTakeover: true, // Defaults to negotiated value.
    serverNoContextTakeover: true, // Defaults to negotiated value.
    serverMaxWindowBits: 10, // Defaults to negotiated value.
    // Below options specified as default values.
    concurrencyLimit: 10, // Limits zlib concurrency for perf.
    threshold: 1024, // Size (in bytes) below which messages
    // should not be compressed if context takeover is disabled.
  },
});

wss.on("connection", (socket, request) => {
  socket.on("message", (data, isBinary) => {
    const uuid = ab2str(data as any);
    sockets.set(uuid, socket);
    console.log(uuid + " on message");
    socket.onclose = (event: WebSocket.CloseEvent) => {
      sockets.delete(uuid);
      console.log(uuid + "on close");
    };
  });
});
