import React from "react";
import ReactDOM from "react-dom/client";
import { v4 as uuidv4 } from "uuid";

import reportWebVitals from "./reportWebVitals";

import Dashboard from "./Dashboard";

import "./index.css";
import { WS_BASE_URL } from "./Api";
import Event from "./Event";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement
);

(globalThis as any).SESSION_ID = uuidv4();

const ws = new WebSocket(WS_BASE_URL);
ws.onopen = () => {
  console.log("ws connected");
  ws.send((globalThis as any).SESSION_ID);
};
ws.onmessage = (ev) => {
  console.log(ev.data);
  Event.emit("flush", ev.data);
};

root.render(
  <React.StrictMode>
    <Dashboard />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
