// JavaScript optimizations
window.createBlobUrlFromChunks = (chunks) => {
    try {
        // Sử dụng Web Workers để xử lý chunks
        const worker = new Worker(createWorkerBlob());

        return new Promise((resolve, reject) => {
            worker.onmessage = (e) => {
                if (e.data.error) {
                    reject(e.data.error);
                } else {
                    resolve(e.data.url);
                }
                worker.terminate();
            };

            worker.postMessage({ chunks });
        });
    } catch (error) {
        console.error('Error creating Blob URL:', error);
        return null;
    }
};

function createWorkerBlob() {
    const workerCode = `
        self.onmessage = async function(e) {
            try {
                const { chunks } = e.data;
                
                // Sử dụng TransformStream để xử lý chunks hiệu quả
                const stream = new TransformStream();
                const writer = stream.writable.getWriter();
                
                // Xử lý từng chunk
                for (const chunk of chunks) {
                    await writer.write(new Uint8Array(chunk));
                }
                await writer.close();
                
                // Tạo blob từ stream
                const blob = await new Response(stream.readable).blob();
                const url = URL.createObjectURL(blob);
                
                self.postMessage({ url });
            } catch (error) {
                self.postMessage({ error: error.message });
            }
        };
    `;

    const blob = new Blob([workerCode], { type: 'application/javascript' });
    return URL.createObjectURL(blob);
}


window.cleanupBlobUrl = (url) => {
    if (url && url.startsWith('blob:')) {
        URL.revokeObjectURL(url);
    }
};