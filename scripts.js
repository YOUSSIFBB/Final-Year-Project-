document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = document.getElementById('target').value;

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target }),
                });

                const data = await response.json();
                const output = document.getElementById('output');
                if (data.success) {
                    output.textContent = JSON.stringify(data.scan_output, null, 2);
                } else {
                    output.textContent = `Error: ${data.error}`;
                }
            } catch (error) {
                output.textContent = `Error: ${error.message}`;
            }
        });
    }
});


