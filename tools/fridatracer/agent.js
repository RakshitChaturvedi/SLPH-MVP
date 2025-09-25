/**
 * Frida Agent: agent.js
 * 
 * this script is the spy that gets injected into the target binary.
 * It's job is to find and hook the "recv" function, which is a 
 * standard function used by programs to receive network data.
 * 
 * When the program calls `recv`, this script will:
 *  1. (onEnter): Note the memory address where the data will be stored.
 *  2. (onLeave): After `recv` finishes, find out which function in the 
 *  program called `recv`. This is our "message handler".
 *  3. Send a message back to our python controller containing the mapping:
 * { buffer_address: "...", handler_function: "..."}
 */
'use strict';

try {
    send({ type: 'log', payload: 'Agent script started (ApiResolver version).'});

    const recvBuffers = new Map();
    var recvPtr = null;

    // Use ApiResolver for a more robust function search. This is a modern
    // alternative to Module.findExportByName.
    const resolver = new ApiResolver('module');
    const matches = resolver.enumerateMatches('exports:*!recv');

    if (matches.length === 0) {
        send({ type: 'error', payload: "ApiResolver could not find an export for 'recv'." });
    } else {
        // Use the address of the first match found.
        recvPtr = matches[0].address; 
        send({ type: 'log', payload: `ApiResolver found 'recv' at address: ${recvPtr}` });

        Interceptor.attach(recvPtr, {
            onEnter: function (args) {
                try {
                    // args[1] is the buffer pointer we need to save.
                    recvBuffers.set(this.threadId, args[1]);
                } catch (e) {
                    send({ type: 'error', payload: `Error in onEnter: ${e.message}` });
                }
            },
            onLeave: function (retval) {
                try {
                    const bytesRead = retval.toInt32();
                    if (bytesRead <= 0) {
                        recvBuffers.delete(this.threadId);
                        return;
                    }

                    const bufferAddress = recvBuffers.get(this.threadId);
                    if (!bufferAddress) {
                        return;
                    }

                    const returnAddress = this.context.sp.readPointer();
                    const handlerSymbol = DebugSymbol.fromAddress(returnAddress);
                    const handlerName = handlerSymbol.name || returnAddress.toString();

                    send({
                        type: 'trace',
                        payload: {
                            buffer_address: bufferAddress.toString(),
                            bytes_read: bytesRead,
                            handler_function: handlerName
                        }
                    });
                    
                    recvBuffers.delete(this.threadId);
                } catch (e) {
                    send({ type: 'error', payload: `Error in onLeave: ${e.message}` });
                    recvBuffers.delete(this.threadId);
                }
            }
        });
        send({ type: 'log', payload: 'Interceptor attached successfully.' });
    }
} catch (error) {
    // This will catch any unexpected top-level errors during initialization.
    send({ type: 'error', payload: `A top-level error occurred: ${error.message}` });
}