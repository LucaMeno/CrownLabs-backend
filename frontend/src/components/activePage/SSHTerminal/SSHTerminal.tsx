<<<<<<< HEAD
import React, { useEffect, useContext } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { useXTerm } from 'react-xtermjs';
import { AuthContext } from '../../../contexts/AuthContext';
import './SSHTerminal.css';

const SSHTerminal: React.FC = () => {
  const { namespace = '', VMname: nomeVM = '' } = useParams();
  const [searchParams] = useSearchParams();
  const prettyName = searchParams.get('prettyName') ?? '';
  const { ref, instance } = useXTerm();
  const { token } = useContext(AuthContext);

  useEffect(() => {
    if (!instance) return;

    instance.options = {
      cursorBlink: true,
      scrollback: 10000,
      theme: {
        background: '#000000',
        foreground: '#ffffff',
      },
    };

    instance.focus();

    const ws = new WebSocket(`wss://${window.location.host}/ws`);

    ws.onopen = () => {
      ws.send(
        JSON.stringify({
          namespace,
          vmName: nomeVM,
          token,
=======
import React, { useContext, useEffect, useRef } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";
import { AuthContext } from '../../../contexts/AuthContext';

const { token } = useContext(AuthContext);

const hideScrollbarStyle: React.CSSProperties = {
  lineHeight: 1.2,
  width: "100%",
  height: "100vh",
  overflow: "hidden",
  scrollbarWidth: "none",
  msOverflowStyle: "none",
  backgroundColor: "black",
};

const injectGlobalStyle = () => {
  const style = document.createElement("style");
  style.innerHTML = `
    html, body {
      margin: 0;
      padding: 0;
      overflow: hidden;
      background-color: black;
    }
    ::-webkit-scrollbar {
      width: 0;
      background: transparent;
    }
  `;
  document.head.appendChild(style);
};

const SSHTerminal: React.FC = () => {
  const { namespace, name: nomeVM } = useParams<{ namespace: string; name: string }>();
  const [searchParams] = useSearchParams();
  const prettyName = searchParams.get("prettyName") ?? "";
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);

  useEffect(() => {
    injectGlobalStyle();
    if (!containerRef.current) return;

  
    const term = new Terminal({
      cursorBlink: true,
      convertEol: true,
      scrollback: 10000,
      theme: { background: "#000000" },
    });
    term.open(containerRef.current);
    term.focus();
    termRef.current = term;

    const wsProtocol = "wss";
    const socket = new WebSocket(`${wsProtocol}://${window.location.host}/ws`);

    socket.onopen = () => {
      socket.send(
        JSON.stringify({
          namespace: namespace ?? "",
          vm: nomeVM ?? "",
          token: token ?? "",
>>>>>>> b56e561c990780d641633ed421940642c86099f4
        })
      );

      if (prettyName)
<<<<<<< HEAD
        instance.writeln(`\x1b[1;36m📡 Connecting to: ${prettyName}\x1b[0m`);
      instance.writeln('[✔] SSH connection success.\r\n');
    };

    ws.onmessage = (ev) => {
      instance.write(ev.data);
    };

    ws.onerror = () => {
      instance.writeln('[✖] Connection error.\r\n');
    };

    ws.onclose = () => {
      instance.writeln('[●] Connection closed.\r\n');
    };

    instance.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    return () => {
      ws.close();
      instance.dispose();
    };
  }, [instance, namespace, nomeVM, prettyName, token]);

  return <div ref={ref} className="ssh-terminal" />;
=======
        term.writeln(`\x1b[1;36m📡 Connecting to: ${prettyName}\x1b[0m`);
      term.writeln("[✔] SSH connection success.\r\n");
    };

    socket.onmessage = (ev) => term.write(ev.data as string);
    socket.onerror = () => term.writeln("[✖] Connection error.\r\n");
    socket.onclose = () => term.writeln("[●] Connection closed.\r\n");

    term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(data);
    });

    return () => {
      socket.close();
      term.dispose();
    };
  }, [namespace, nomeVM, prettyName]);

  return <div ref={containerRef} style={hideScrollbarStyle} />;
>>>>>>> b56e561c990780d641633ed421940642c86099f4
};

export default SSHTerminal;
