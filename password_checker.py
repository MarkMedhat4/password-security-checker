#!/usr/bin/env python3
"""
Password Security Checker - v2.0
Includes common password detection
Author: Your Name
Date: 2026
"""

import re
from pathlib import Path
import math

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


def check_password_strength(password, common_passwords=None):
    """
    Analyze password strength based on multiple criteria
    
    Args:
        password (str): Password to check
        common_passwords (set): Set of common passwords to check against
        
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
            'strength_color': "\033[91m",  # Red
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
             'entropy': calculate_entropy(password),      # ← أضف
            'crack_time': 'Instant (in breach databases)'  # ← أضف
        }
    
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
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
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
        'entropy': entropy,           # ← أضف
        'crack_time': crack_time      # ← أضف
    }

def print_result(result):
    """Pretty print the analysis result with entropy information"""
    print("\n" + "="*60)
    print(f"Password Analysis for: {'*' * len(result['password'])}")
    print("="*60)
    
    # Strength
    print(f"\n{result['strength_color']}Strength: {result['strength']}{result['reset_color']}")
    print(f"Score: {result['score']}/{result['max_score']}")
    
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
    print("\n🔐 Password Security Checker v2.0")
    print("="*60)
    print("Check the strength of your passwords!")
    print("Type 'quit' to exit\n")
    
    # Load common passwords once at startup
    print("📂 Loading common passwords database...")
    common_passwords = load_common_passwords('common_passwords.txt')
    print()
    
    while True:
        password = input("Enter password to check: ").strip()
        
        if password.lower() == 'quit':
            print("\n👋 Thanks for using Password Checker!")
            break
        
        if not password:
            print("⚠️  Please enter a password\n")
            continue
        
        result = check_password_strength(password, common_passwords)
        print_result(result)


if __name__ == "__main__":
    main()
