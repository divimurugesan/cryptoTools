"""
AI-Based Cryptanalysis Tool - Flask Web Application
"""

from flask import Flask, render_template, request, jsonify
from cryptanalysis_core import CipherBreaker
import io
import base64

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None

app = Flask(__name__)
breaker = CipherBreaker()

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze ciphertext and attempt to break it"""
    data = request.json
    ciphertext = data.get('ciphertext', '')
    cipher_type = data.get('cipher_type', 'auto')
    
    if not ciphertext:
        return jsonify({'error': 'No ciphertext provided'}), 400
    
    result = {}
    
    # Determine cipher type if auto
    if cipher_type == 'auto':
        detected_type = breaker.classify_cipher_type(ciphertext)
        result['detected_type'] = detected_type
    else:
        detected_type = cipher_type
    
    # Break the cipher based on type
    try:
        if detected_type == 'Caesar' or detected_type == 'auto':
            result['caesar'] = breaker.break_caesar_cipher(ciphertext)
        if detected_type == 'Vigenère' or detected_type == 'auto':
            result['vigenere'] = breaker.break_vigenere_cipher(ciphertext)
        if detected_type == 'Monoalphabetic' or detected_type == 'auto':
            result['monoalphabetic'] = breaker.break_monoalphabetic_cipher(ciphertext)
        if detected_type == 'Playfair' or detected_type == 'auto':
            result['playfair'] = breaker.break_playfair_cipher(ciphertext)
        
        # Add frequency analysis visualization
        freq_data = breaker.frequency_analysis(ciphertext)
        result['frequency_analysis'] = freq_data
        result['frequency_chart'] = create_frequency_chart(freq_data)
        
        # Add n-gram analysis
        result['ngram_score'] = breaker.ngram_score(ciphertext)
        result['dictionary_score'] = breaker.dictionary_attack_score(ciphertext)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    return jsonify(result)

def create_frequency_chart(freq_data):
    """Create frequency chart visualization"""
    if plt is None:
        return None
    # Sort by frequency
    sorted_freq = dict(sorted(freq_data.items(), key=lambda x: x[1], reverse=True))
    
    plt.figure(figsize=(10, 6))
    plt.bar(sorted_freq.keys(), sorted_freq.values(), color='skyblue')
    plt.xlabel('Letters')
    plt.ylabel('Frequency (%)')
    plt.title('Letter Frequency Analysis')
    plt.xticks(list('abcdefghijklmnopqrstuvwxyz'))
    plt.grid(axis='y', alpha=0.3)
    
    # Save to base64 string
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    plt.close()
    
    return plot_url

@app.route('/compare', methods=['POST'])
def compare_methods():
    """Compare different cryptanalysis methods"""
    data = request.json
    ciphertext = data.get('ciphertext', '')
    
    if not ciphertext:
        return jsonify({'error': 'No ciphertext provided'}), 400
    
    results = {
        'caesar': breaker.break_caesar_cipher(ciphertext),
        'vigenere': breaker.break_vigenere_cipher(ciphertext),
        'monoalphabetic': breaker.break_monoalphabetic_cipher(ciphertext),
        'playfair': breaker.break_playfair_cipher(ciphertext)
    }
    
    # Calculate confidence scores
    for method, result in results.items():
        if 'confidence' not in result:
            result['confidence'] = calculate_confidence(result.get('plaintext', ''))
    
    return jsonify(results)

def calculate_confidence(text):
    """Calculate confidence score for decrypted text"""
    if not text:
        return 0
    
    dict_score = breaker.dictionary_attack_score(text)
    ngram_score = breaker.ngram_score(text)
    
    return (dict_score * 0.6 + (ngram_score / 10) * 0.4)

@app.route('/train', methods=['POST'])
def train_model():
    """Train ML model with custom data"""
    data = request.json
    ciphertexts = data.get('ciphertexts', [])
    plaintexts = data.get('plaintexts', [])
    
    if not ciphertexts or not plaintexts:
        return jsonify({'error': 'Training data required'}), 400
    
    try:
        breaker.train_ml_model(ciphertexts, plaintexts)
        return jsonify({'status': 'success', 'message': 'Model trained successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
