import express from "express";
import cors from "cors";
import { spawn } from "child_process";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

app.get("/", (request, response) => {
  response.send("insight web backend works!");
});

app.get("/register", (request, response) => {
  if (request.query.ip) {
    const childProcess = spawn(
      "frida",
      ["-H", `${request.query.ip}`, "gadget", "--no-pause", "-l", "_agent.js"],
      { cwd: "../insight-agent" }
    );
    childProcess.stderr.on("data", function (data) {
      console.error(data.toString());
    });

    childProcess.stdout.on("data", function (data) {
      console.log(data.toString());
    });

    childProcess.on("close", (code) => {
      console.log(`child process exited with code ${code}`);
    });

    response.send("insight web backend works!");
  } else {
  }
});

app.listen(8080, () => {
  console.log("insight web backend listening on port 8080!");
});
