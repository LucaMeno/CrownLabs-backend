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
        })
      );

      if (prettyName)
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
};

export default SSHTerminal;
