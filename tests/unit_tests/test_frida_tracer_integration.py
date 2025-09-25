import unittest
import sys
import os
import subprocess
import csv
from pathlib import Path

# --- Test Environment Setup ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FRIDA_TRACER_SCRIPT = PROJECT_ROOT / 'tools' / 'fridatracer' / 'frida_tracer.py'
AGENT_SCRIPT = PROJECT_ROOT / 'tools' / 'fridatracer' / 'agent.js'

class TestFridaTracerIntegration(unittest.TestCase):
    """ An integration test for the frida_tracer.py script and it's agent.js.
        This test runs the tracer as a subprocess against a live, binary (curl)
        and validates the output.
    """

    def setUp(self):
        self.output_log_path = Path("test_trace.log").resolve()

        # the target binary for tracing. cURL is good as its widely available
        # and makes predictable 'recv' calls.
        self.target_binary = "/usr/bin/curl"

        # Clean up any old log files
        if self.output_log_path.exists():
            os.remove(self.output_log_path)

    def tearDown(self):
        if self.output_log_path.exists():
            os.remove(self.output_log_path)

    def test_frida_tracer_generates_valid_log(self):
        """ Tests the end-to-end tracing process. execites the tracer,
            waits for it to complete, and then inspects the generated
            log file to ensure it contains valid formatted data.
        """
        # skip test if curl or tracer script doesnt exist
        if not os.path.exists(self.target_binary):
            self.skipTest(f"Target binary '{self.target_binary}' not found.")
        if not FRIDA_TRACER_SCRIPT.exists():
            self.fail(f"Frida tracer script not found at {FRIDA_TRACER_SCRIPT}")
        if not AGENT_SCRIPT.exists():
            self.fail(f"Frida agent script not found at {AGENT_SCRIPT}")

        # Arrange: construct the command to execute the tracer script.
        command = [
            sys.executable,     # current python interpretor
            str(FRIDA_TRACER_SCRIPT),
            "--output",
            str(self.output_log_path),
            "--",               # seperator for tracer vs target args.
            self.target_binary,
            "-s",              # silent mode for curl
            "http://example.com"
        ]

        # Act: run the tracer as a subprocess and wait for it to finish
        try:
            # add "> /dev/null" to cmd to hide curl's HTML output
            # requires running it through a shell.
            process = subprocess.run(
                " ".join(command) + " > /dev/null",
                shell=True,
                timeout=20,     # timeout to prevent hangs.
                check=True,     # raise exception if process fails
            )
            self.assertEqual(
                process.returncode,
                0,
                "Tracer script exited with an error."
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            self.fail(f"Frida tracer subprocess failed: {e}")

        # Assert: Check the contents of generated log file.
        self.assertTrue(self.output_log_path.exists(), "Output log file was not created.")

        with open(self.output_log_path, 'r') as f:
            reader = csv.reader(f)

            # 1. check valid header raww
            header = next(reader)
            self.assertEqual(header, ["buffer_address", "bytes_read", "handler_function"])

            # 2. check atleast 1 data raw.
            try:
                first_raw = next(reader)
            except StopIteration:
                self.fail("Log file is empty or contains only a header.")

            # 3. validate structure & content of first data raw
            self.assertEqual(len(first_raw), 3, "Data row does not have exactly 3 cols.")

            buffer_addr, bytes_read, handler_func = first_raw

            self.assertTrue(buffer_addr.startswith("0x"), "Buffer address is not a valid hex value.")
            self.assertTrue(int(bytes_read) > 0, "Bytes read should be a positive integer.")
            self.assertTrue(handler_func.startswith("0x"), "Handler function is not a valid hex address.")

if __name__ == '__main__':
    unittest.main()


