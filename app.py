#!/usr/bin/env python3
"""
Password Security Checker - Flask Web Application
Provides web interface for password strength analysis
"""

from flask import Flask, render_template, request, jsonify
import re
from pathlib import Path
import math
import hashlib
import requests

app = Flask(__name__)

# Global variable to store common passwords (loaded once at startup)
COMMON_PASSWORDS = set()


def load_common_passwords(file_path='common_passwords.txt'):
    """Load common passwords from file"""
    common_passwords = set()
    try:
        if Path(file_path).is_file():
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        common_passwords.add(password.lower())
        print(f"✅ Loaded {len(common_passwords):,} common passwords")
    except Exception as e:
        print(f"⚠️  Error loading common passwords: {e}")
    return common_passwords


def is_common_password(password, common_passwords):
    """Check if password is common"""
    return password.lower() in common_passwords


def calculate_entropy(password):
    """Calculate password entropy"""
    pool_size = 0
    
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'\d', password):
        pool_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\\/;\'`~]', password):
        pool_size += 33
    
    if pool_size == 0:
        return 0.0
    
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def estimate_crack_time(entropy):
    """Estimate crack time based on entropy"""
    if entropy == 0:
        return "Instant"
    
    total_combinations = 2 ** entropy
    avg_guesses = total_combinations / 2
    guesses_per_second = 1_000_000_000
    seconds = avg_guesses / guesses_per_second
    
    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    elif seconds < 31536000 * 100:
        return f"{seconds / 31536000:.2f} years"
    elif seconds < 31536000 * 1000000:
        return f"{seconds / 31536000 / 1000:.2f} thousand years"
    elif seconds < 31536000 * 1000000000:
        return f"{seconds / 31536000 / 1000000:.2f} million years"
    else:
        return f"{seconds / 31536000 / 1000000000:.2f} billion years"


def check_pwned_password(password):
    """Check if password has been breached"""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    hash_prefix = sha1_hash[:5]
    hash_suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for line in hashes:
                if ':' in line:
                    returned_suffix, count = line.split(':')
                    if returned_suffix == hash_suffix:
                        return {'pwned': True, 'count': int(count)}
            return {'pwned': False, 'count': 0}
        else:
            return {'pwned': None, 'count': 0, 'error': 'API error'}
    except Exception as e:
        return {'pwned': None, 'count': 0, 'error': str(e)}


def check_password_strength(password, check_breaches=True):
    """Main password checking function"""
    score = 0
    max_score = 6
    feedback = []
    
    # Check if common password
    if is_common_password(password, COMMON_PASSWORDS):
        return {
            'strength': 'Very Weak',
            'strength_level': 'very-weak',
            'score': 0,
            'max_score': max_score,
            'percentage': 0,
            'feedback': [
                'This is a commonly used password!',
                'It appears in breach databases.',
                'NEVER use this password!',
                'Use a unique, random password.'
            ],
            'entropy': calculate_entropy(password),
            'crack_time': 'Instant',
            'breach_status': 'common',
            'breach_count': 'N/A'
        }
    
    # Check breaches
    breach_result = {'pwned': None, 'count': 0}
    if check_breaches:
        breach_result = check_pwned_password(password)
        if breach_result['pwned']:
            feedback.insert(0, f"Found in {breach_result['count']:,} data breaches!")
            feedback.insert(1, "This password is publicly known!")
    
    # Length checks
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Consider 12+ characters")
    
    # Character type checks
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z)")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z)")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add numbers (0-9)")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\\/;\'`~]', password):
        score += 1
    else:
        feedback.append("Add special characters (!@#$...)")
    
    # Determine strength
    if score <= 2:
        strength = "Weak"
        strength_level = "weak"
    elif score <= 4:
        strength = "Medium"
        strength_level = "medium"
    else:
        strength = "Strong"
        strength_level = "strong"
    
    # Override if breached
    if breach_result.get('pwned'):
        strength = "Compromised"
        strength_level = "compromised"
    
    # Calculate metrics
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    percentage = (score / max_score) * 100
    
    # Breach status
    if breach_result.get('pwned') is True:
        breach_status = 'breached'
        breach_count = breach_result['count']
    elif breach_result.get('pwned') is False:
        breach_status = 'clean'
        breach_count = 0
    else:
        breach_status = 'unknown'
        breach_count = 'N/A'
    
    return {
        'strength': strength,
        'strength_level': strength_level,
        'score': score,
        'max_score': max_score,
        'percentage': percentage,
        'feedback': feedback,
        'entropy': entropy,
        'crack_time': crack_time,
        'breach_status': breach_status,
        'breach_count': breach_count,
        'length': len(password)
    }


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    """API endpoint for password checking"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    check_breaches = data.get('check_breaches', True)
    result = check_password_strength(password, check_breaches)
    
    return jsonify(result)


if __name__ == '__main__':
    print("\n🔐 Password Security Checker - Web Interface")
    print("=" * 60)
    print("Loading resources...")
    
    # Load common passwords at startup
    COMMON_PASSWORDS = load_common_passwords('common_passwords.txt')
    
    print("\n✅ Server ready!")
    print("📱 Open your browser at: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
