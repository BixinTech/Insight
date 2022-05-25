import express from "express";
import cors from "cors";
import { ChildProcessWithoutNullStreams, spawn } from "child_process";

class ResponseCode {
  static SUCCESS: number = 8000;
  static FAILURE: number = 8001;
}

interface Response {
  code: number;
  message: string;
  data: any;
}

function getNanoSecondTime() {
  const hrTime = process.hrtime();
  return hrTime[0] * 1000000000 + hrTime[1];
}

const registry = new Map<string, ChildProcessWithoutNullStreams>();

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
  if (request.query.ip) {
    const registerTime = getNanoSecondTime();

    const childProcess = spawn(
      "frida",
      ["-H", `${request.query.ip}`, "gadget", "--no-pause", "-l", "_agent.js"],
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
              date: registerTime,
            },
          } as Response);
          registry.set(request.query.ip as string, childProcess);
        } else {
          response.send({
            code: ResponseCode.FAILURE,
            message: "insight agent connection failed",
          } as Response);
        }
      }
    }, 5000);
  } else {
    response.send({
      code: ResponseCode.FAILURE,
      message: "parameter ip is missing",
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

app.listen(8080, () => {
  console.log("insight web backend listening on port 8080!");
});
