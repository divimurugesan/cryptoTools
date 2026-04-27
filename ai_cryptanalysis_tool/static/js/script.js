// AI Cryptanalysis Tool - Interactive JavaScript

function analyze() {
    const ciphertext = document.getElementById('ciphertext').value;
    const cipherType = document.getElementById('cipher-type').value;
    
    if (!ciphertext.trim()) {
        alert('Please enter ciphertext to analyze');
        return;
    }
    
    showLoading();
    
    $.ajax({
        url: '/analyze',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            ciphertext: ciphertext,
            cipher_type: cipherType
        }),
        success: function(data) {
            displayResults(data);
            if (data.frequency_chart) {
                displayFrequencyChart(data.frequency_chart);
            }
            updateMetrics(data);
        },
        error: function(xhr, status, error) {
            alert('Error: ' + xhr.responseJSON.error);
            hideLoading();
        }
    });
}

function compareMethods() {
    const ciphertext = document.getElementById('ciphertext').value;
    
    if (!ciphertext.trim()) {
        alert('Please enter ciphertext to compare methods');
        return;
    }
    
    showLoading();
    
    $.ajax({
        url: '/compare',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            ciphertext: ciphertext
        }),
        success: function(data) {
            displayComparisonResults(data);
            hideLoading();
        },
        error: function(xhr, status, error) {
            alert('Error: ' + xhr.responseJSON.error);
            hideLoading();
        }
    });
}

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    let html = '';
    
    if (data.detected_type) {
        html += `<div class="alert alert-info">Detected Cipher Type: <strong>${data.detected_type}</strong></div>`;
    }
    
    if (data.caesar) {
        html += `
            <div class="result-item">
                <h6>🔐 Caesar Cipher Analysis</h6>
                <p><strong>Shift:</strong> ${data.caesar.shift}</p>
                <p><strong>Decrypted Text:</strong> ${data.caesar.plaintext}</p>
                <p><strong>Confidence:</strong> ${(data.caesar.confidence * 100).toFixed(2)}%</p>
            </div>
        `;
    }
    
    if (data.vigenere) {
        html += `
            <div class="result-item">
                <h6>🔑 Vigenère Cipher Analysis</h6>
                <p><strong>Key:</strong> ${data.vigenere.key}</p>
                <p><strong>Decrypted Text:</strong> ${data.vigenere.plaintext}</p>
                <p><strong>Confidence:</strong> ${(data.vigenere.confidence * 100).toFixed(2)}%</p>
            </div>
        `;
    }
    
    if (data.monoalphabetic) {
        html += `
            <div class="result-item">
                <h6>📝 Monoalphabetic Substitution Analysis</h6>
                <p><strong>Decrypted Text:</strong> ${data.monoalphabetic.plaintext}</p>
                <p><strong>Confidence:</strong> ${(data.monoalphabetic.confidence * 100).toFixed(2)}%</p>
                <details>
                    <summary>View Substitution Mapping</summary>
                    <pre>${JSON.stringify(data.monoalphabetic.mapping, null, 2)}</pre>
                </details>
            </div>
        `;
    }
    
    if (data.playfair) {
        html += `
            <div class="result-item">
                <h6>🎮 Playfair Cipher Analysis</h6>
                <p><strong>Key:</strong> ${data.playfair.key}</p>
                <p><strong>Decrypted Text:</strong> ${data.playfair.plaintext}</p>
                <p><strong>Confidence:</strong> ${(data.playfair.confidence * 100).toFixed(2)}%</p>
            </div>
        `;
    }
    
    if (!data.caesar && !data.vigenere && !data.monoalphabetic && !data.playfair) {
        html += '<p class="text-muted">No analysis results available. Try a different cipher type.</p>';
    }
    
    resultsDiv.innerHTML = html;
    hideLoading();
}

function displayComparisonResults(data) {
    const resultsDiv = document.getElementById('results');
    let html = '<h6>Method Comparison</h6>';
    
    // Find best method
    let bestMethod = null;
    let bestConfidence = 0;
    
    for (const [method, result] of Object.entries(data)) {
        if (result.confidence > bestConfidence) {
            bestConfidence = result.confidence;
            bestMethod = method;
        }
    }
    
    for (const [method, result] of Object.entries(data)) {
        const isBest = method === bestMethod;
        html += `
            <div class="result-item" style="${isBest ? 'border-left-color: #28a745;' : ''}">
                <h6>${method.toUpperCase()} ${isBest ? '⭐ Best Result' : ''}</h6>
                <p><strong>Decrypted:</strong> ${result.plaintext.substring(0, 100)}...</p>
                <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(2)}%</p>
                ${result.key ? `<p><strong>Key:</strong> ${result.key}</p>` : ''}
            </div>
        `;
    }
    
    resultsDiv.innerHTML = html;
}

function displayFrequencyChart(chartData) {
    const chartDiv = document.getElementById('frequency-chart');
    chartDiv.innerHTML = `<img src="data:image/png;base64,${chartData}" class="img-fluid" alt="Frequency Analysis Chart">`;
}

function updateMetrics(data) {
    if (data.ngram_score !== undefined) {
        document.getElementById('ngram-score').innerHTML = 
            `<span class="badge bg-info">${data.ngram_score.toFixed(3)}</span>`;
    }
    
    if (data.dictionary_score !== undefined) {
        document.getElementById('dict-score').innerHTML = 
            `<span class="badge bg-success">${(data.dictionary_score * 100).toFixed(1)}%</span>`;
    }
    
    // Calculate overall confidence from best result
    let bestConfidence = 0;
    if (data.caesar && data.caesar.confidence > bestConfidence) bestConfidence = data.caesar.confidence;
    if (data.vigenere && data.vigenere.confidence > bestConfidence) bestConfidence = data.vigenere.confidence;
    if (data.monoalphabetic && data.monoalphabetic.confidence > bestConfidence) bestConfidence = data.monoalphabetic.confidence;
    if (data.playfair && data.playfair.confidence > bestConfidence) bestConfidence = data.playfair.confidence;
    
    document.getElementById('confidence').innerHTML = 
        `<span class="badge bg-warning">${(bestConfidence * 100).toFixed(1)}%</span>`;
}

function showLoading() {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `
        <div class="spinner">
            <div class="bounce1"></div>
            <div class="bounce2"></div>
            <div class="bounce3"></div>
            <p class="mt-2">Analyzing ciphertext with AI...</p>
        </div>
    `;
}

function hideLoading() {
    // Loading will be replaced by actual results
}

// Add example ciphertexts for testing
function loadExample() {
    const examples = {
        caesar: "khoor zruog",  // Hello world with shift 3
        vigenere: "lzwf akh twlz",  // Key: "key"
        monoalphabetic: "gwkky rgwkq"  // Simple substitution
    };
    
    const selectExample = confirm("Load example Caesar cipher?");
    if (selectExample) {
        document.getElementById('ciphertext').value = examples.caesar;
        document.getElementById('cipher-type').value = "Caesar";
    }
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'Enter') {
        analyze();
    }
});