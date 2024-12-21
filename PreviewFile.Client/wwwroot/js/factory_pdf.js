window.createBlobUrl = (bytes) => {
    try {
        // Tạo Uint8Array từ byte array
        const uint8Array = new Uint8Array(bytes);

        // Tạo Blob với type là PDF
        const blob = new Blob([uint8Array], { type: 'application/pdf' });

        // Tạo URL từ Blob
        const url = URL.createObjectURL(blob);
        console.log('Created Blob URL:', url);

        return url;
    } catch (error) {
        console.error('Error creating Blob URL:', error);
        return null;
    }
};

// Cleanup function để gọi khi component unmount
window.revokeBlobUrl = (url) => {
    if (url && url.startsWith('blob:')) {
        URL.revokeObjectURL(url);
        console.log('Revoked Blob URL:', url);
    }
};