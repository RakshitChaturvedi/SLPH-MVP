import pika
import time
import os
import sys
import json

# --- Path Setup ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

# --- RabbitMQ Config ---
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
CORRELATION_QUEUE = "correlation_task_queue"

def process_task(channel, method, properties, body):
    """ This is the callback func that'll be executed every time
        a message is received from the queue.
    """
    try:
        print(f"[*] Received new task. Raw body: {body.decode()}")

        # decode the mssg body from bytes to a string, then parse as json
        message = json.loads(body.decode())
        project_id = message.get("project_id")

        if not project_id:
            print("[-] Message is missing 'project_id'. Discarding.", file=sys.stderr)
            # acknowledge mssg even if its malformed to remove it from queue
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        print(f"[+] Processing task for project_id: {project_id}")

        # The actual analysis will happen here.
        time.sleep(2)

        print(f"[+] Task compelte for project_id: {project_id}")

        # send an acknowledgement to RabbitMQ to confirm receipt and processing.
        # tells rabbitmq that the mssg can be safely removed from queue.
        channel.basic_ack(delivery_tag = method.delivery_tag)
    
    except json.JSONDecodeError:
        print("[-] Failed to decode JSON from message to body. Discarding.", file=sys.stderr)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}", file=sys.stderr)
        # We don't acknowledge the message to have it re-queued. 
        # for now, we will ack to prevent loops.
        channel.basic_ack(delivery_tag=method.delivery_tag)

def main():
    """ Main function for the worker.
        Establishes a connection to RabbitMQ and
        Starts consuming mssgs from queue in a blocking loop.
    """

    print("[*] Correlation service worker starting...")
    connection = None

    while True:
        try:
            print(f"[*] Connecting to RabbitMQ at '{RABBITMQ_HOST}'...")
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBITMQ_HOST)
            )
            channel = connection.channel()

            # declare the queue. 
            # durable=true -> mssgs survive rabbitmq restart.
            # declaration is idempotent 
            # (won't create new queue if one w same name and properties exists.)
            channel.queue_declare(queue=CORRELATION_QUEUE, durable=True)
            print(f"[*] Waiting for tasks on queue '{CORRELATION_QUEUE}'. To exit, press CTRL+C")

            # tell rabbitmq that this worker shouldnt be given
            # more than 1 mssg at a time.
            # its a form of rate-limiting or "QoS" (Quality Of Service).
            channel.basic_qos(prefetch_count=1)

            # register 'process_task' func as callback for new mssgs.
            channel.basic_consume(
                queue=CORRELATION_QUEUE,
                on_message_callback=process_task
            )

            channel.start_consuming()
        
        except pika.exceptions.AMQPConnectionError as e:
            print(f"[-] RabbitMQ connection failed: {e}. Retrying in 5 seconds...", file=sys.stderr)
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] Shutting down worker...")
            if connection and connection.is_open:
                connection.close()
            break
        except Exception as e:
            print(f"[-] An unexpected error occured in the main loop: {e}", file=sys.stderr)
            time.sleep(5)


if __name__ == '__main__':
    main()
            
