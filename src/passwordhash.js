const {
    fetch, Request, WebAssembly, console, TextEncoder, document,
    Uint8Array, DataView, Promise, Worker, location, self, URL,
} = new Function('return this')();

const current_script_src = document?.currentScript?.src;


if (current_script_src) {
    run_script();
} else {
    run_worker();
}


function run_script () {
    let next_callid = 0;

    const promises = Object.create(null);

    const worker_promise = (
        fetch(current_script_src, { cache: 'force-cache' }).
        then(response => response.blob()).
        then(blob => {
            let new_worker;
            const url = URL.createObjectURL(blob)
            try {
                new_worker = new Worker(url);
            } finally {
                URL.revokeObjectURL(url);
            }
            new_worker.addEventListener('message', ({ data: { success, data, callid } }) => {
                const resolve_reject = promises[callid];
                delete promises[callid];
                if (resolve_reject) {
                    resolve_reject[+success](data);
                }
            });
            return new_worker;
        })
    );

    self.argon2_hash = ({password, salt, key, ad}) => {
        if ((salt || '').length < 8) {
            return Promise.reject('no salt');
        }

        return new Promise((resolve, reject) => {
            const callid = ++next_callid;
            const data = { callid, password, salt, key, ad };

            promises[callid] = [reject, resolve];

            worker_promise.then(worker => { worker.postMessage(data); }).catch(() => {
                console.log('Could not initialize worker');
                delete promises[callid];
                reject();
            });
        });
    };
}


function run_worker () {
    const parallelism = 1;
    const tag_length = 32;
    const memory_size_kb = 64 * 1024;
    const iterations = 4;
    const version = 0x13;
    const hash_type = 0;  // d

    const to_hash = [];

    function argon2_fn (obj) {
        to_hash.push(obj);
    }

    function set_fn (fn) {
        try {
            while (to_hash.length) {
                try {
                    // Process as LIFO queue. The last message is most likely the most important.
                    fn(to_hash.pop());
                } catch (ex) {
                    console.warn('Error in chained callback', ex);
                }
            }
        } finally {
            argon2_fn = fn;
        }
    }

    self.addEventListener('message', ({ data }) => {
        argon2_fn(data);
    });


    fetch(wasm_data_uri).
    then(response => response.arrayBuffer()).
    then(buffer => WebAssembly.instantiate(buffer)).
    then(obj => {
        const { instance: { exports: { B, argon2, memory: { buffer } } } } = obj;

        set_fn(function ({ callid, password, salt, key, ad }) {
            let success = false;
            let data;
            try {
                const u8view = new Uint8Array(buffer);
                try {
                    const dataview = new DataView(buffer);

                    dataview.setUint32(B + 4 * 0, parallelism,    true);
                    dataview.setUint32(B + 4 * 1, tag_length,     true);
                    dataview.setUint32(B + 4 * 2, memory_size_kb, true);
                    dataview.setUint32(B + 4 * 3, iterations,     true);
                    dataview.setUint32(B + 4 * 4, version,        true);
                    dataview.setUint32(B + 4 * 5, hash_type,      true);

                    let memory_pos = B + 4 * 6;

                    function put_str (s) {
                        if (!s) {
                            dataview.setUint32(memory_pos, 0, true);
                            memory_pos += 4;
                        } else {
                            const arr = (new TextEncoder).encode(s);
                            const { length } = arr;

                            dataview.setUint32(memory_pos, length, true);
                            memory_pos += 4;

                            u8view.set(arr, memory_pos);
                            memory_pos += length;
                        }
                    }

                    put_str(password);
                    put_str(salt);
                    put_str(key);
                    put_str(ad);

                    success = !!argon2(memory_pos - B);
                    data = u8view.slice(B, B + tag_length);
                } finally {
                    u8view.subarray(B, B + 1024 * memory_size_kb).fill(0);
                }
            } catch (ex) {
                console.warn('Could not hash', ex);
            }
            self.postMessage({ success, data, callid });
        });
    }).
    catch(ex => {
        console.warn('Could not initialize WebAssembly', ex);

        set_fn(function (data) {
            const { callid } = data;
            const success = false;
            self.postMessage({ success, callid });
        });
    });
}
