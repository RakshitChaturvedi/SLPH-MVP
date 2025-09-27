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
    send({ type: 'log', payload: 'Agent script started.' });

    const recvPtr = DebugSymbol.fromName('recv').address;
    const recvfromPtr = DebugSymbol.fromName('recvfrom').address;
    const recvmsgPtr = DebugSymbol.fromName('recvmsg').address;

    const functionsToHook = {
        'recv': recvPtr,
        'recvfrom': recvfromPtr,
        'recvmsg': recvmsgPtr,
    };

    let hook_count = 0;
    for (const [funcName, funcPtr] of Object.entries(functionsToHook)) {
        if (funcPtr && !funcPtr.isNull()) {
            hook_count++;
            Interceptor.attach(funcPtr, {
                // clean up any previous Stalker session for this thread.
                onEnter: function(args) {
                    const threadId = this.threadId;
                    if (threadStates.has(threadId)) {
                        Stalker.unfollow(threadId);
                        threadStates.delete(threadId);
                    }
                    let state = {
                        buffer: ptr(0),
                        size: 0,
                        isStalking: false,
                        msghdr_ptr: null
                    };
                    if (funcName === 'recvmsg') {
                        state.msghdr_ptr = args[1]; // parse this in onLeave
                    } else {
                        state.buffer = args[1]; // direct buffer for recv/recfrom
                    }
                    threadStates.set(threadId, state);
                },
                // start the new Stalker session.
                onLeave: function (retval) {
                    const bytesRead = retval.toInt32();
                    const threadId = this.threadId;
                    const state = threadStates.get(threadId);

                    if (bytesRead <= 0 || !state) {
                        return;
                    }

                    if (state.msghdr_ptr) {
                        for (let i = 0; i < 8; i++) {
                            try {
                                const iov_ptr = state.msghdr_ptr.add(i*8).readPointer();
                                if (iov_ptr.toInt32() > 4096) {
                                    const buffer_len = iov_ptr.add(Process.pointerSize).readU64();
                                    if (buffer_len.toNumber() >= bytesRead) {
                                        state.buffer = iov_ptr.readPointer();
                                        break;
                                    }
                                }
                            } catch (e) {/** Ignore */}
                        }
                    }

                    if (state.buffer.isNull()){
                        return;
                    }

                    state.size = bytesRead;

                    Stalker.follow(threadId, {
                        transform: function (iterator) {
                            let instruction;
                            while ((instruction = iterator.next()) !== null ) {
                                if (isMemoryRead(instruction)) {
                                    send({
                                        type: 'instruction',
                                        payload: {
                                            mnemonic: instruction.mnemonic,
                                        }
                                    });
                                }
                                iterator.keep();
                            }
                        }
                    })
                }
            });
        }
    }
    
    if (hook_count > 0) {
        send({ type: 'log', payload: `[SUCCESS] Successfully attached to ${hook_count} recv* functions.` });
    } else {
        send({ type: 'error', payload: 'Could not find any recv* functions to hook.' });
    }

} catch (error) {
    send({ type: 'error', payload: `[FATAL ERROR] A top-level error occurred: ${error.message}` });
}