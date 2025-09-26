/**
 * Frida Agent: agent.js (Upgraded for Instruction-Level Tracing)
 * Its job is to find and hook the "recv" function to trace how the
 * received data is processed at an instruction-by-instruction level.
 * * When the program calls `recv`, this script will:
 * 
 * 1. (onEnter): Stop any previous tracing on the current thread to avoid overlap.
 * It then records the memory address where the incoming data will be stored.
 * 
 * * 2. (onLeave): After `recv` finishes, if data was received, it starts
 * Frida.Stalker on the current thread. Stalker will follow the program's
 * execution from this point forward.
 * 
 * * 3. (Stalker Transform): The Stalker will analyze every block of code before
 * it is executed. We instruct it to insert a "callout" after every
 * instruction that reads from memory.
 */
'use strict';

const threadStates = new Map();

function isMemoryRead(instruction) {
    return instruction.operands.some(op => op.type === 'mem' && op.access.includes('r'));
}

try {
    send({ type: 'log', payload: 'Agent script started (Stalker version 8, Diagnostic).' });

    const resolver = new ApiResolver('module');
    const matches = resolver.enumerateMatches('exports:*!recv');

    if (matches.length === 0) {
        send({ type: 'error', payload: "ApiResolver could not find 'recv'." });
    } else {
        const recvPtr = matches[0].address;
        send({ type: 'log', payload: `ApiResolver found 'recv' at: ${recvPtr}` });

        Interceptor.attach(recvPtr, {
            onEnter: function (args) {
                const threadId = this.threadId;
                let state = threadStates.get(threadId);

                if (state && state.isStalking) {
                    Stalker.unfollow(threadId);
                    state.isStalking = false;
                }
                
                state = {
                    buffer: args[1],
                    size: 0,
                    isStalking: false
                };
                threadStates.set(threadId, state);
            },
            onLeave: function (retval) {
                const bytesRead = retval.toInt32();
                const threadId = this.threadId;
                const state = threadStates.get(threadId);

                if (bytesRead <= 0 || !state) {
                    threadStates.delete(threadId);
                    return;
                }

                state.size = bytesRead;
                state.isStalking = true;
                
                Stalker.follow(threadId, {
                    transform: function (iterator) {
                        let instruction;
                        while ((instruction = iterator.next()) !== null) {
                            if (isMemoryRead(instruction)) {
                                send({
                                    type: 'mem_read_instruction',
                                    payload: {
                                        instr_address: instruction.address.toString(),
                                        instr_string: instruction.toString()
                                    }
                                });
                            }
                            iterator.keep();
                        }
                    }
                });
            }
        });
        send({ type: 'log', payload: 'Interceptor attached successfully.' });
    }
} catch (error) {
    send({ type: 'error', payload: `A top-level error occurred: ${error.message}` });
}