import * as React from "react";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";
import { FitAddon } from "xterm-addon-fit";
import { SearchAddon } from "xterm-addon-search";
import Event from "./Event";

interface XtermProps {}

interface XtermState {}

export default class XTerm extends React.Component<XtermProps, XtermState> {
  terminal: Terminal | null = null;
  div: HTMLDivElement | null = null;
  themeListener?: (...args: any[]) => void;

  componentDidMount() {
    let theme = {
      background: "#ffffff",
      foreground: "#000000",
      selection: "#000000",
    };
    this.terminal = new Terminal({
      theme: theme,
      scrollback: Number.MAX_SAFE_INTEGER,
    });
    const fitAddon = new FitAddon();
    const searchAddon = new SearchAddon();
    this.terminal.loadAddon(fitAddon);
    this.terminal.loadAddon(searchAddon);
    if (this.div) {
      this.terminal.open(this.div);
    }
    fitAddon.fit();

    Event.addListener("flush", (value) => {
      const log = JSON.parse(value) as any;
      console.log(log);
      this.terminal?.writeln(log.signature);
      const array = (log.stackTrace as string).split(",");

      array.forEach((stackTrace: string) => {
        this.terminal?.writeln(stackTrace + ",");
      });
    });
  }

  componentWillUnmount() {
    if (this.terminal) {
      this.terminal.dispose();
      this.terminal = null;
    }

    Event.removeAllListeners("flush");
  }

  render() {
    return (
      <div
        ref={(ref) => (this.div = ref)}
        style={{ height: "calc(100vh - 280px)" }}
      />
    );
  }
}
