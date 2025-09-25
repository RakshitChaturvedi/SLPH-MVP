import frida
import sys
import argparse
import threading
from pathlib import Path

log_file = None

# Create a threading event to signal when the target process has exited
exit_event = threading.Event()

def on_message(message, data):
    """
    Callback for messages received from the Frida agent.
    """
    global log_file

    if message.get('type') == 'send':
        payload = message.get('payload', {})
        agent_message_type = payload.get('type')
        agent_payload = payload.get('payload')

        if agent_message_type == 'trace':
            trace_data = agent_payload or {}
            log_line = (
                f"{trace_data.get('buffer_address', 'N/A')},"
                f"{trace_data.get('bytes_read', 0)},"
                f"{trace_data.get('handler_function', 'N/A')}\n"
            )
            print(f"[+] Trace: {log_line.strip()}")
            if log_file:
                log_file.write(log_line)
                log_file.flush()

        elif agent_message_type == 'log':
            print(f"[*] Agent Log: {agent_payload}")

        elif agent_message_type == 'error':
            print(f"[-] Agent Error: {agent_payload}", file=sys.stderr)

    elif message.get('type') == 'error':
        print(f"[-] Frida Error: {message.get('description')}", file=sys.stderr)


def on_detached(reason):
    """
    Callback for when Frida detaches from the target process.
    This happens when the target process exits.
    """
    print(f"[*] Detached from process (reason: {reason}). Exiting tracer.")
    exit_event.set() # Signal the main thread to stop waiting and exit

def main():
    parser = argparse.ArgumentParser(
        description="Launch a binary and trace its 'recv' calls using Frida.",
        usage='%(prog)s [options] /path/to/binary [binary args...]'
    )
    parser.add_argument(
        "-o", "--output",
        default="trace.log",
        help="The file to save the trace log to (default: trace.log)."
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

    target_binary = Path(target_cmd[0])

    if not target_binary.is_file():
        print(f"[-] Error: Binary not found at '{target_binary}'", file=sys.stderr)
        sys.exit(1)

    agent_path = Path(__file__).resolve().parent / "agent.js"
    if not agent_path.is_file():
        print(f"[-] Error: agent.js not found at '{agent_path}'", file=sys.stderr)
        sys.exit(1)
        
    with open(agent_path, 'r') as f:
        agent_code = f.read()

    global log_file
    session = None
    try:
        log_file = open(args.output, 'w')
        log_file.write("buffer_address,bytes_read,handler_function\n")
        log_file.flush()

        print(f"[*] Spawning and attaching to: `{' '.join(target_cmd)}`...")
        
        device = frida.get_local_device()
        pid = device.spawn(target_cmd)
        session = device.attach(pid)

        # Register our on_detached callback
        session.on('detached', on_detached)

        script = session.create_script(agent_code)
        script.on('message', on_message)
        script.load()

        device.resume(pid)
        print("[+] Process resumed. Waiting for trace data or process exit...")

        # Instead of waiting for keyboard input, wait for the exit event.
        # This will block until on_detached is called or Ctrl+C is pressed.
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
        print("[*] Script finished.")

if __name__ == '__main__':
    main()
