#!/usr/bin/env python3
"""
Password Security Checker - v3.0
Features:
- Basic strength analysis (6 criteria)
- Common password detection (10K+ database)
- Entropy calculation
- Crack time estimation
- Breach detection via HaveIBeenPwned API

Author: Commandos
Date: 2026
"""

import re
from pathlib import Path
import math
import hashlib
import requests


def load_common_passwords(file_path='common_passwords.txt'):
    """
    Load common passwords from file into a set for fast lookup
    
    Args:
        file_path (str): Path to the common passwords file
        
    Returns:
        set: Set of common passwords (lowercase)
    """
    common_passwords = set()
    
    try:
        # Check if file exists
        if not Path(file_path).is_file():
            print(f"⚠️  Warning: {file_path} not found. Skipping common password check.")
            return common_passwords
        
        # Load passwords
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password:  # Skip empty lines
                    common_passwords.add(password.lower())
        
        print(f"✅ Loaded {len(common_passwords):,} common passwords")
        return common_passwords
        
    except Exception as e:
        print(f"⚠️  Error loading common passwords: {e}")
        return common_passwords


def is_common_password(password, common_passwords):
    """
    Check if password exists in common passwords database
    
    Args:
        password (str): Password to check
        common_passwords (set): Set of common passwords
        
    Returns:
        bool: True if password is common, False otherwise
    """
    return password.lower() in common_passwords


def calculate_entropy(password):
    """
    Calculate password entropy (randomness measure in bits)
    Higher entropy = stronger password
    
    Args:
        password (str): Password to analyze
        
    Returns:
        float: Entropy value in bits
    """
    pool_size = 0
    
    # Determine character pool size
    if re.search(r'[a-z]', password):
        pool_size += 26  # lowercase letters
    
    if re.search(r'[A-Z]', password):
        pool_size += 26  # uppercase letters
    
    if re.search(r'\d', password):
        pool_size += 10  # digits
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\\/;\'`~]', password):
        pool_size += 33  # special characters
    
    # If no recognizable characters, return 0
    if pool_size == 0:
        return 0.0
    
    # Calculate entropy: log2(pool_size^length)
    # This equals: length * log2(pool_size)
    entropy = len(password) * math.log2(pool_size)
    
    return round(entropy, 2)


def estimate_crack_time(entropy):
    """
    Estimate time to crack password based on entropy
    Assumes attacker can try 1 billion (10^9) guesses per second
    
    Args:
        entropy (float): Password entropy in bits
        
    Returns:
        str: Human-readable time estimate
    """
    if entropy == 0:
        return "Instant (0 seconds)"
    
    # Total possible combinations
    total_combinations = 2 ** entropy
    
    # Average guesses needed (assume password is found halfway through)
    avg_guesses = total_combinations / 2
    
    # Guesses per second (modern GPU: ~1 billion/sec for simple hashes)
    guesses_per_second = 1_000_000_000
    
    # Time in seconds
    seconds = avg_guesses / guesses_per_second
    
    # Convert to human-readable format
    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f} hours"
    elif seconds < 31536000:
        days = seconds / 86400
        return f"{days:.2f} days"
    elif seconds < 31536000 * 100:
        years = seconds / 31536000
        return f"{years:.2f} years"
    elif seconds < 31536000 * 1000:
        years = seconds / 31536000
        return f"{years:.0f} years"
    elif seconds < 31536000 * 1000000:
        years = seconds / 31536000
        return f"{years/1000:.2f} thousand years"
    elif seconds < 31536000 * 1000000000:
        years = seconds / 31536000
        return f"{years/1000000:.2f} million years"
    else:
        years = seconds / 31536000
        return f"{years/1000000000:.2f} billion years"


def check_pwned_password(password):
    """
    Check if password has been leaked in data breaches
    Uses HaveIBeenPwned API with k-anonymity model
    
    The k-anonymity model ensures privacy:
    1. Hash the password with SHA-1
    2. Send only first 5 characters of hash to API
    3. API returns all hashes starting with those 5 chars
    4. We check locally if our full hash is in the results
    
    Args:
        password (str): Password to check
        
    Returns:
        dict: {
            'pwned': bool or None (None if API error),
            'count': int (number of times seen in breaches)
        }
    """
    # Create SHA-1 hash of password
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Split hash: first 5 chars (prefix) + rest (suffix)
    hash_prefix = sha1_hash[:5]
    hash_suffix = sha1_hash[5:]
    
    # API endpoint
    url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"
    
    try:
        # Query API with timeout
        response = requests.get(url, timeout=5)
        
        # Check if request was successful
        if response.status_code == 200:
            # Parse response - each line is: HASH_SUFFIX:COUNT
            hashes = response.text.splitlines()
            
            # Check if our hash suffix is in the response
            for line in hashes:
                if ':' in line:
                    returned_suffix, count = line.split(':')
                    if returned_suffix == hash_suffix:
                        return {
                            'pwned': True,
                            'count': int(count)
                        }
            
            # Hash not found in breaches
            return {
                'pwned': False,
                'count': 0
            }
        else:
            # API returned an error
            return {
                'pwned': None,
                'count': 0,
                'error': f'API returned status code {response.status_code}'
            }
    
    except requests.exceptions.Timeout:
        # Request timed out
        return {
            'pwned': None,
            'count': 0,
            'error': 'Request timed out'
        }
    
    except requests.exceptions.RequestException as e:
        # Other network errors
        return {
            'pwned': None,
            'count': 0,
            'error': f'Network error: {str(e)}'
        }
    
    except Exception as e:
        # Unexpected errors
        return {
            'pwned': None,
            'count': 0,
            'error': f'Unexpected error: {str(e)}'
        }


def check_password_strength(password, common_passwords=None, check_breaches=True):
    """
    Analyze password strength based on multiple criteria
    
    Args:
        password (str): Password to check
        common_passwords (set): Set of common passwords to check against
        check_breaches (bool): Whether to check against breach databases
        
    Returns:
        dict: Analysis results with strength, score, and feedback
    """
    score = 0
    max_score = 6
    feedback = []
    
    # CRITICAL CHECK: Common password detection
    if common_passwords and is_common_password(password, common_passwords):
        return {
            'password': password,
            'strength': '🔴 Very Weak (Common Password)',
            'strength_color': "\033[91m",
            'reset_color': "\033[0m",
            'score': 0,
            'max_score': max_score,
            'feedback': [
                '❌ CRITICAL: This is a commonly used password!',
                '⚠️  It appears in breach databases and password lists.',
                '🚨 NEVER use this password - it can be cracked instantly!',
                '💡 Use a unique, random password instead.'
            ],
            'is_common': True,
            'entropy': calculate_entropy(password),
            'crack_time': 'Instant (in breach databases)',
            'breach_check': {'pwned': True, 'count': 'N/A (common password)'}
        }
    
    # BREACH CHECK: Check against HaveIBeenPwned database
    breach_result = {'pwned': None, 'count': 0}
    if check_breaches:
        print("  🔍 Checking against breach databases...", end='', flush=True)
        breach_result = check_pwned_password(password)
        print(" Done!")
        
        if breach_result['pwned']:
            # Password found in breaches - CRITICAL
            feedback.insert(0, f"🚨 CRITICAL: This password was found in {breach_result['count']:,} data breaches!")
            feedback.insert(1, "⚠️  This password is publicly known and should NEVER be used!")
        elif breach_result['pwned'] is None:
            # API error - still show other results
            if 'error' in breach_result:
                feedback.append(f"⚠️  Could not check breach database: {breach_result['error']}")
    
    # Criterion 1: Length >= 8
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password must be at least 8 characters long")
    
    # Criterion 2: Length >= 12 (bonus)
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("💡 Consider using 12+ characters for better security")
    
    # Criterion 3: Uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")
    
    # Criterion 4: Lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters (a-z)")
    
    # Criterion 5: Digits
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("❌ Add numbers (0-9)")
    
    # Criterion 6: Special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\\/;\'`~]', password):
        score += 1
    else:
        feedback.append("❌ Add special characters (!@#$%^&*...)")
    
    # Determine strength level
    if score <= 2:
        strength = "🔴 Weak"
        strength_color = "\033[91m"  # Red
    elif score <= 4:
        strength = "🟡 Medium"
        strength_color = "\033[93m"  # Yellow
    else:
        strength = "🟢 Strong"
        strength_color = "\033[92m"  # Green
    
    # Override strength if password is breached
    if breach_result.get('pwned'):
        strength = '🔴 Compromised (Found in Breaches)'
        strength_color = "\033[91m"
    
    reset_color = "\033[0m"
    
    # Calculate entropy and crack time
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    
    return {
        'password': password,
        'strength': strength,
        'strength_color': strength_color,
        'reset_color': reset_color,
        'score': score,
        'max_score': max_score,
        'feedback': feedback,
        'is_common': False,
        'entropy': entropy,
        'crack_time': crack_time,
        'breach_check': breach_result
    }


def print_result(result):
    """Pretty print the analysis result with all security information"""
    print("\n" + "="*60)
    print(f"Password Analysis for: {'*' * len(result['password'])}")
    print("="*60)
    
    # Strength
    print(f"\n{result['strength_color']}Strength: {result['strength']}{result['reset_color']}")
    print(f"Score: {result['score']}/{result['max_score']}")
    
    # Breach check results
    breach = result.get('breach_check', {})
    if breach.get('pwned') is True:
        print(f"\n🚨 BREACH STATUS: COMPROMISED")
        if isinstance(breach.get('count'), int):
            print(f"  Found in {breach['count']:,} data breaches")
        else:
            print(f"  {breach.get('count', 'Found in breach databases')}")
    elif breach.get('pwned') is False:
        print(f"\n✅ BREACH STATUS: Clean")
        print(f"  Not found in known data breaches")
    elif breach.get('pwned') is None and 'error' in breach:
        print(f"\n⚠️  BREACH STATUS: Unknown")
        print(f"  {breach.get('error', 'Could not check')}")
    
    # Entropy and crack time
    print(f"\n📊 Security Metrics:")
    print(f"  • Entropy: {result.get('entropy', 0):.2f} bits")
    print(f"  • Estimated Crack Time: {result.get('crack_time', 'N/A')}")
    
    # Character composition
    password = result['password']
    composition = []
    if re.search(r'[a-z]', password):
        composition.append("lowercase")
    if re.search(r'[A-Z]', password):
        composition.append("UPPERCASE")
    if re.search(r'\d', password):
        composition.append("digits")
    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\\/;\'`~]', password):
        composition.append("special")
    
    if composition:
        print(f"  • Character Types: {', '.join(composition)}")
        print(f"  • Length: {len(password)} characters")
    
    # Feedback
    if result['feedback']:
        print("\n📋 Recommendations:")
        for tip in result['feedback']:
            print(f"  {tip}")
    else:
        print("\n✅ Excellent! Your password meets all criteria.")
    
    print("="*60 + "\n")


def main():
    """Main function - Interactive mode"""
    print("\n🔐 Password Security Checker v3.0")
    print("="*60)
    print("Now with HaveIBeenPwned breach detection!")
    print("Type 'quit' to exit\n")
    
    # Load common passwords once at startup
    print("📂 Loading common passwords database...")
    common_passwords = load_common_passwords('common_passwords.txt')
    print()
    
    # Ask about breach checking
    print("Enable breach detection? (checks against 800M+ leaked passwords)")
    breach_choice = input("Check breaches? (y/n, default: y): ").strip().lower()
    check_breaches = breach_choice != 'n'
    print()
    
    while True:
        password = input("Enter password to check: ").strip()
        
        if password.lower() == 'quit':
            print("\n👋 Thanks for using Password Checker!")
            break
        
        if not password:
            print("⚠️  Please enter a password\n")
            continue
        
        result = check_password_strength(password, common_passwords, check_breaches)
        print_result(result)


if __name__ == "__main__":
    main()
