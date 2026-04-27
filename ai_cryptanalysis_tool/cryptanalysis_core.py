"""
AI-Based Cryptanalysis Core Module
Breaks classical ciphers using ML and NLP techniques
"""

import os
import re
from collections import Counter

# Optional dependencies. The app should still run in a limited mode if these
# are unavailable in the environment.
try:
    import numpy as np
except Exception:
    np = None

try:
    import nltk
    from nltk.util import ngrams as nltk_ngrams
    from nltk.corpus import words as nltk_words
    _HAS_NLTK = True
except Exception:
    nltk = None
    nltk_ngrams = None
    nltk_words = None
    _HAS_NLTK = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import CountVectorizer
except Exception:
    RandomForestClassifier = None
    CountVectorizer = None

_BUILTIN_WORDS = {
    "the", "and", "that", "have", "for", "not", "with", "you", "this", "but",
    "his", "from", "they", "say", "her", "she", "will", "one", "all", "would",
    "there", "their", "what", "about", "which", "when", "make", "can", "like",
    "time", "just", "know", "take", "people", "into", "year", "your", "good",
    "some", "could", "them", "see", "other", "than", "then", "now", "look",
    "only", "come", "its", "over", "think", "also", "back", "after", "use",
    "two", "how", "our", "work", "first", "well", "way", "even", "new",
    "want", "because", "any", "these", "give", "day", "most", "us", "is", "are",
    "a", "an", "to", "of", "in", "on", "at", "as", "by", "be"
}

def _load_wordlist():
    """Load a word list from NLTK or local data file, with a small fallback."""
    if _HAS_NLTK:
        try:
            # Ensure the corpus exists; avoid download in restricted envs.
            nltk.data.find("corpora/words")
            return set(nltk_words.words())
        except Exception:
            pass

    data_path = os.path.join(os.path.dirname(__file__), "data", "english_words.txt")
    try:
        with open(data_path, "r", encoding="utf-8") as handle:
            words_from_file = {line.strip().lower() for line in handle if line.strip()}
        if words_from_file:
            return words_from_file
    except Exception:
        pass

    return set(_BUILTIN_WORDS)

def _ngrams(text, n):
    """Return n-grams using NLTK if available, else a lightweight fallback."""
    if _HAS_NLTK and nltk_ngrams is not None:
        return list(nltk_ngrams(text, n))
    return [tuple(text[i:i + n]) for i in range(len(text) - n + 1)]

def _mean_vector(vectors):
    """Compute mean vector without numpy if needed."""
    if not vectors:
        return []
    if np is not None:
        return np.mean(vectors, axis=0)
    length = len(vectors[0])
    sums = [0.0] * length
    for vec in vectors:
        for i in range(length):
            sums[i] += vec[i]
    return [s / len(vectors) for s in sums]

class CipherBreaker:
    def __init__(self):
        self.english_words = _load_wordlist()
        self.frequency_english = {
            'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
            'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
            'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
            'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
            'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974, 'z': 0.074
        }
        self.model = None
        self.vectorizer = None
        if CountVectorizer is not None:
            self.vectorizer = CountVectorizer(analyzer='char', ngram_range=(1, 3))
        
    def preprocess_text(self, text):
        """Clean and preprocess text"""
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        return text.lower()
    
    def frequency_analysis(self, text):
        """Perform frequency analysis on text"""
        text = self.preprocess_text(text)
        text = re.sub(r'\s+', '', text)
        freq = Counter(text)
        total = sum(freq.values())
        
        if total == 0:
            return {}
        
        freq_percent = {char: (count/total)*100 for char, count in freq.items()}
        return freq_percent
    
    def chi_squared_score(self, text):
        """Calculate chi-squared score for frequency analysis"""
        freq = self.frequency_analysis(text)
        score = 0
        for char, expected in self.frequency_english.items():
            observed = freq.get(char, 0)
            if observed > 0:
                score += ((observed - expected) ** 2) / expected
        return score
    
    def ngram_score(self, text, n=3):
        """Score text based on common n-grams"""
        text = self.preprocess_text(text)
        text = re.sub(r'\s+', '', text)
        
        if len(text) < n:
            return 0
            
        n_grams = _ngrams(text, n)
        # Common English trigrams
        common_trigrams = {'the', 'and', 'ing', 'ent', 'ion', 'tio', 'for', 'nde'}
        
        score = 0
        for gram in n_grams:
            gram_str = ''.join(gram)
            if gram_str in common_trigrams:
                score += 1
            elif gram_str in {'th', 'he', 'in', 'en', 'nt', 're', 'er', 'an'}:
                score += 0.5
                
        return score / max(1, len(n_grams))
    
    def dictionary_attack_score(self, text):
        """Score text based on dictionary word matches"""
        text = self.preprocess_text(text)
        words_in_text = text.split()
        
        if not words_in_text:
            return 0
            
        matches = sum(1 for word in words_in_text if word in self.english_words)
        return matches / len(words_in_text)
    
    def break_caesar_cipher(self, ciphertext):
        """Break Caesar cipher using frequency analysis"""
        ciphertext = self.preprocess_text(ciphertext)
        best_shift = 0
        best_score = float('inf')
        best_plaintext = ""
        
        for shift in range(26):
            decrypted = self.caesar_decrypt(ciphertext, shift)
            score = self.chi_squared_score(decrypted)
            
            if score < best_score:
                best_score = score
                best_shift = shift
                best_plaintext = decrypted
                
        return {
            'plaintext': best_plaintext,
            'shift': best_shift,
            'confidence': 1 / (1 + best_score/100)
        }
    
    def caesar_decrypt(self, text, shift):
        """Decrypt Caesar cipher with given shift"""
        result = ""
        for char in text:
            if char.isalpha():
                shifted = ord(char) - shift
                if shifted < ord('a'):
                    shifted += 26
                result += chr(shifted)
            else:
                result += char
        return result
    
    def break_vigenere_cipher(self, ciphertext, max_key_length=20):
        """Break Vigenère cipher using Kasiski examination and ML"""
        ciphertext = self.preprocess_text(ciphertext)
        ciphertext = re.sub(r'\s+', '', ciphertext)
        
        # Estimate key length using Kasiski examination
        key_lengths = self.find_key_length(ciphertext, max_key_length)
        
        if not key_lengths:
            return {'plaintext': "Could not determine key length", 'key': ""}
        
        best_key = ""
        best_plaintext = ""
        best_score = float('inf')
        
        for key_len in key_lengths[:3]:  # Try top 3 key lengths
            key = self.find_key(ciphertext, key_len)
            decrypted = self.vigenere_decrypt(ciphertext, key)
            score = self.chi_squared_score(decrypted)
            
            if score < best_score:
                best_score = score
                best_key = key
                best_plaintext = decrypted
        
        return {
            'plaintext': best_plaintext,
            'key': best_key,
            'confidence': 1 / (1 + best_score/50)
        }
    
    def find_key_length(self, ciphertext, max_length):
        """Find key length using Kasiski examination"""
        trigrams = {}
        distances = []
        
        # Find repeated trigrams and their distances
        for i in range(len(ciphertext) - 3):
            trigram = ciphertext[i:i+3]
            if trigram in trigrams:
                distances.append(i - trigrams[trigram])
            else:
                trigrams[trigram] = i
        
        # Score possible key lengths
        key_scores = {}
        for length in range(2, max_length + 1):
            score = sum(1 for d in distances if d % length == 0)
            if score > 0:
                key_scores[length] = score
        
        # Sort by score
        key_lengths = sorted(key_scores.items(), key=lambda x: x[1], reverse=True)
        return [k for k, v in key_lengths[:5]]
    
    def find_key(self, ciphertext, key_length):
        """Find the Vigenère key using frequency analysis"""
        key = ""
        
        for i in range(key_length):
            # Extract letters for this position
            segment = ciphertext[i::key_length]
            best_shift = self.find_caesar_shift(segment)
            key += chr(ord('a') + best_shift)
            
        return key
    
    def find_caesar_shift(self, text):
        """Find best Caesar shift for a text segment"""
        best_shift = 0
        best_score = float('inf')
        
        for shift in range(26):
            decrypted = self.caesar_decrypt(text, shift)
            score = self.chi_squared_score(decrypted)
            
            if score < best_score:
                best_score = score
                best_shift = shift
                
        return best_shift
    
    def vigenere_decrypt(self, ciphertext, key):
        """Decrypt Vigenère cipher with given key"""
        plaintext = ""
        key_length = len(key)
        
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                shift = ord(key[i % key_length]) - ord('a')
                decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
                plaintext += decrypted_char
            else:
                plaintext += char
                
        return plaintext
    
    def break_monoalphabetic_cipher(self, ciphertext, use_ml=True):
        """Break monoalphabetic substitution using ML and frequency analysis"""
        ciphertext = self.preprocess_text(ciphertext)
        
        # Get frequency analysis
        freq = self.frequency_analysis(ciphertext)
        sorted_cipher_letters = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        sorted_english_letters = sorted(self.frequency_english.items(), key=lambda x: x[1], reverse=True)
        
        # Initial substitution mapping based on frequency
        mapping = {}
        for i, (cipher_char, _) in enumerate(sorted_cipher_letters):
            if i < len(sorted_english_letters):
                mapping[cipher_char] = sorted_english_letters[i][0]
        
        # Apply substitution
        decrypted = self.apply_substitution(ciphertext, mapping)
        
        if use_ml:
            # Use ML model to refine mapping
            decrypted = self.ml_refine_decryption(ciphertext, decrypted, mapping)
        
        # Calculate confidence score
        confidence = self.dictionary_attack_score(decrypted) * 0.6 + \
                    (self.ngram_score(decrypted) / 10) * 0.4
        
        return {
            'plaintext': decrypted,
            'mapping': mapping,
            'confidence': min(confidence, 1.0)
        }
    
    def apply_substitution(self, text, mapping):
        """Apply substitution mapping to text"""
        result = ""
        for char in text:
            if char in mapping:
                result += mapping[char]
            else:
                result += char
        return result
    
    def ml_refine_decryption(self, ciphertext, current_plaintext, mapping):
        """Use ML to refine the decryption"""
        # Extract features for each word
        words_cipher = ciphertext.split()
        words_plain = current_plaintext.split()
        
        features = []
        for i, word in enumerate(words_cipher):
            if i < len(words_plain):
                # Features: word length, frequency, n-gram patterns
                word_len = len(word)
                freq_score = sum(self.frequency_english.get(c, 0) for c in words_plain[i])
                ngram_score_val = self.ngram_score(words_plain[i])
                features.append([word_len, freq_score, ngram_score_val])
        
        # Use similarity to refine mapping (simplified ML approach)
        if features:
            avg_features = _mean_vector(features)
            if avg_features[2] < 0.1:  # Low n-gram score indicates potential issues
                # Adjust mapping based on common bigrams
                self.adjust_mapping_for_bigrams(ciphertext, mapping)
                
        return self.apply_substitution(ciphertext, mapping)
    
    def adjust_mapping_for_bigrams(self, text, mapping):
        """Adjust substitution mapping based on common bigrams"""
        # Get most common bigrams in ciphertext
        cipher_bigrams = _ngrams(text, 2)
        cipher_bigram_freq = Counter(cipher_bigrams)
        most_common_cipher_bigrams = [bg for bg, _ in cipher_bigram_freq.most_common(5)]
        
        # Common English bigrams
        common_english_bigrams = ['th', 'he', 'in', 'en', 'nt', 're', 'er']
        
        # Adjust mapping to make cipher bigrams map to common English bigrams
        for cipher_bg in most_common_cipher_bigrams:
            for eng_bg in common_english_bigrams:
                # Check if mapping can be improved
                mapped_bg = mapping.get(cipher_bg[0], '') + mapping.get(cipher_bg[1], '')
                if mapped_bg != eng_bg:
                    # Potential adjustment needed
                    pass
    
    def train_ml_model(self, ciphertexts, plaintexts):
        """Train ML model for cipher classification"""
        if RandomForestClassifier is None:
            raise RuntimeError("ML training requires scikit-learn to be installed.")
        X = []
        y = []
        
        for cipher, plain in zip(ciphertexts, plaintexts):
            # Extract features
            features = self.extract_features(cipher)
            X.append(features)
            y.append(self.classify_cipher_type(cipher, plain))
        
        # Train Random Forest classifier
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        
    def extract_features(self, text):
        """Extract features from ciphertext for ML model"""
        text = self.preprocess_text(text)
        
        # Feature extraction
        freq = self.frequency_analysis(text)
        chi_score = self.chi_squared_score(text)
        ngram_score_val = self.ngram_score(text)
        
        # Index of coincidence
        ic = self.calculate_index_of_coincidence(text)
        
        # Vectorized n-gram features
        if self.vectorizer is not None:
            ngram_features = self.vectorizer.fit_transform([text]).toarray()[0][:10]  # Top 10 features
            return [chi_score, ngram_score_val, ic] + list(ngram_features[:5])

        return [chi_score, ngram_score_val, ic]
    
    def calculate_index_of_coincidence(self, text):
        """Calculate Index of Coincidence"""
        text = re.sub(r'\s+', '', text)
        n = len(text)
        if n < 2:
            return 0
            
        freq = Counter(text)
        ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
        return ic
    
    def classify_cipher_type(self, ciphertext, plaintext=None):
        """Classify the type of cipher used"""
        ic = self.calculate_index_of_coincidence(ciphertext)
        
        if ic < 0.05:
            return "Vigenère"
        elif 0.05 <= ic <= 0.07:
            return "Monoalphabetic"
        else:
            return "Caesar"
    
    def break_playfair_cipher(self, ciphertext):
        """Break Playfair cipher using hill climbing and ML"""
        ciphertext = self.preprocess_text(ciphertext)
        ciphertext = re.sub(r'[^a-z]', '', ciphertext)
        
        # Remove duplicate letters for Playfair
        processed_text = ""
        i = 0
        while i < len(ciphertext):
            if i + 1 < len(ciphertext) and ciphertext[i] == ciphertext[i+1]:
                processed_text += ciphertext[i] + 'x'
                i += 1
            else:
                processed_text += ciphertext[i]
                i += 1
        
        if len(processed_text) % 2 != 0:
            processed_text += 'x'
        
        # Hill climbing approach
        best_score = float('inf')
        best_plaintext = ""
        best_key = ""
        
        # Try multiple random starting keys
        for _ in range(10):
            # Generate random Playfair key
            key = self.generate_random_playfair_key()
            decrypted = self.playfair_decrypt(processed_text, key)
            score = self.chi_squared_score(decrypted)
            
            if score < best_score:
                best_score = score
                best_plaintext = decrypted
                best_key = key
        
        confidence = 1 / (1 + best_score/100)
        
        return {
            'plaintext': best_plaintext,
            'key': best_key,
            'confidence': confidence
        }
    
    def generate_random_playfair_key(self):
        """Generate random Playfair cipher key"""
        import random
        alphabet = list('abcdefghiklmnopqrstuvwxyz')  # i and j combined
        random.shuffle(alphabet)
        return ''.join(alphabet)
    
    def playfair_decrypt(self, ciphertext, key):
        """Decrypt Playfair cipher with given key"""
        # Create Playfair grid
        grid = [[key[i*5 + j] for j in range(5)] for i in range(5)]
        
        # Find position in grid
        pos = {}
        for i in range(5):
            for j in range(5):
                pos[grid[i][j]] = (i, j)
        
        # Decrypt pairs
        plaintext = ""
        for i in range(0, len(ciphertext), 2):
            a, b = ciphertext[i], ciphertext[i+1]
            if a == b:
                b = 'x'
            
            row_a, col_a = pos[a]
            row_b, col_b = pos[b]
            
            if row_a == row_b:
                plaintext += grid[row_a][(col_a - 1) % 5]
                plaintext += grid[row_b][(col_b - 1) % 5]
            elif col_a == col_b:
                plaintext += grid[(row_a - 1) % 5][col_a]
                plaintext += grid[(row_b - 1) % 5][col_b]
            else:
                plaintext += grid[row_a][col_b]
                plaintext += grid[row_b][col_a]
        
        return plaintext
