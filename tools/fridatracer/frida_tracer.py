import frida
import sys
import argparse
import threading
import json
from pathlib import Path

log_file = None
exit_event = threading.Event()

def on_message(message, data):
    global log_file

    if message.get('type') == 'send':
        payload = message.get('payload', {})
        agent_message_type = payload.get('type')
        agent_payload = payload.get('payload')

        if agent_message_type == 'mem_read_instruction':
            trace_data = agent_payload or {}
            print(f"[+] Found Instruction: {trace_data}")
            if log_file:
                log_file.write(json.dumps(trace_data) + '\n')
                log_file.flush()

        elif agent_message_type == 'log':
            print(f"[*] Agent Log: {agent_payload}")

        elif agent_message_type == 'error':
            print(f"[-] Agent Error: {agent_payload}", file=sys.stderr)

    elif message.get('type') == 'error':
        print(f"[-] Frida Error: {message.get('description')}", file=sys.stderr)

def on_detached(reason):
    print(f"\n[*] Detached from process (reason: {reason}). Exiting tracer.")
    exit_event.set()

def main():
    parser = argparse.ArgumentParser(
        description="Launch a binary and trace memory reads from 'recv' calls.",
        usage='%(prog)s [options] /path/to/binary [binary args...]'
    )
    parser.add_argument(
        "-o", "--output",
        default="trace.jsonl",
        help="The file to save the trace log to (default: trace.jsonl)."
    )
    parser.add_argument('target', nargs=argparse.REMAINDER, help='Path to the target binary and its arguments')
    
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target_cmd = args.target
    if target_cmd and target_cmd[0] == '--':
        target_cmd.pop(0)

    if not target_cmd:
        print("[-] Error: No binary path specified.", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    agent_path = Path(__file__).resolve().parent / "agent.js"
    if not agent_path.is_file():
        print(f"[-] Error: agent.js not found at '{agent_path}'", file=sys.stderr)
        sys.exit(1)
        
    with open(agent_path, 'r', encoding='utf-8') as f:
        agent_code = f.read()

    global log_file
    session = None
    try:
        log_file = open(args.output, 'w')

        print(f"[*] Spawning and attaching to: `{' '.join(target_cmd)}`...")
        
        device = frida.get_local_device()
        pid = device.spawn(target_cmd)
        session = device.attach(pid)
        
        session.on('detached', on_detached)

        script = session.create_script(agent_code)
        script.on('message', on_message)
        script.load()

        device.resume(pid)
        print("[+] Process resumed. Waiting for trace data... (Press Ctrl+C to stop)")
        
        exit_event.wait()

    except KeyboardInterrupt:
        print("\n[*] Ctrl+C detected. Detaching from process...")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        if session and not session.is_detached:
            session.detach()
        if log_file and not log_file.closed:
            log_file.close()
            print(f"[*] Trace data saved to '{args.output}'")
        print("[*] Script finished.")

if __name__ == '__main__':
    main()
