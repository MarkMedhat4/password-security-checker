#!/usr/bin/env python3
"""
Password Security Checker - v2.0
Includes common password detection
Author: Your Name
Date: 2026
"""

import re
from pathlib import Path


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
            'is_common': True
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
    
    return {
        'password': password,
        'strength': strength,
        'strength_color': strength_color,
        'reset_color': reset_color,
        'score': score,
        'max_score': max_score,
        'feedback': feedback,
        'is_common': False
    }


def print_result(result):
    """Pretty print the analysis result"""
    print("\n" + "="*60)
    print(f"Password Analysis for: {'*' * len(result['password'])}")
    print("="*60)
    print(f"\n{result['strength_color']}Strength: {result['strength']}{result['reset_color']}")
    print(f"Score: {result['score']}/{result['max_score']}")
    
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
