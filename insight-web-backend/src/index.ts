import express from "express";
import cors from "cors";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

app.get("/", (request, response) => {
  response.send("insight web backend works!");
});

app.get("/register", (request, response) => {
  response.send("insight web backend works!");
});

app.listen(8080, () => {
  console.log("insight web backend listening on port 8080!");
});
