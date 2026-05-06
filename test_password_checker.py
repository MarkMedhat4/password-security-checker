#!/usr/bin/env python3
"""
Unit Tests for Password Security Checker
Tests all core functionality
"""

import unittest
import sys
from pathlib import Path

# Import functions from password_checker.py
sys.path.insert(0, str(Path(__file__).parent))
from password_checker import (
    calculate_entropy,
    estimate_crack_time,
    is_common_password,
    check_password_strength
)


class TestPasswordChecker(unittest.TestCase):
    """Test cases for password security checker"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Sample common passwords for testing
        self.common_passwords = {
            'password', '123456', 'qwerty', 
            'abc123', 'letmein'
        }
    
    # ==================== Entropy Tests ====================
    
    def test_entropy_lowercase_only(self):
        """Test entropy calculation for lowercase-only password"""
        entropy = calculate_entropy("password")
        # 8 chars * log2(26) ≈ 37.6
        self.assertGreater(entropy, 35)
        self.assertLess(entropy, 40)
    
    def test_entropy_mixed_case(self):
        """Test entropy calculation for mixed case password"""
        entropy = calculate_entropy("Password")
        # 8 chars * log2(52) ≈ 45.6
        self.assertGreater(entropy, 43)
        self.assertLess(entropy, 48)
    
    def test_entropy_complex(self):
        """Test entropy calculation for complex password"""
        entropy = calculate_entropy("P@ssw0rd!")
        # 9 chars * log2(95) ≈ 59.5
        self.assertGreater(entropy, 55)
        self.assertLess(entropy, 65)
    
    def test_entropy_empty(self):
        """Test entropy calculation for empty password"""
        entropy = calculate_entropy("")
        self.assertEqual(entropy, 0.0)
    
    # ==================== Crack Time Tests ====================
    
    def test_crack_time_weak(self):
        """Test crack time for weak password"""
        crack_time = estimate_crack_time(30)
        self.assertIn("second", crack_time.lower())
    
    def test_crack_time_strong(self):
        """Test crack time for strong password"""
        crack_time = estimate_crack_time(100)
        self.assertIn("year", crack_time.lower())
    
    def test_crack_time_zero(self):
        """Test crack time for zero entropy"""
        crack_time = estimate_crack_time(0)
        self.assertIn("Instant", crack_time)
    
    # ==================== Common Password Tests ====================
    
    def test_common_password_detection(self):
        """Test detection of common passwords"""
        self.assertTrue(
            is_common_password("password", self.common_passwords)
        )
        self.assertTrue(
            is_common_password("PASSWORD", self.common_passwords)  # Case insensitive
        )
    
    def test_unique_password_detection(self):
        """Test that unique passwords are not flagged"""
        self.assertFalse(
            is_common_password("MyUniqueP@ss2024!", self.common_passwords)
        )
    
    # ==================== Strength Check Tests ====================
    
    def test_weak_password(self):
        """Test weak password detection"""
        result = check_password_strength("pass", check_breaches=False)
        self.assertEqual(result['score'], 1)  # Only lowercase
        self.assertIn("Weak", result['strength'])
    
    def test_medium_password(self):
        """Test medium strength password"""
        result = check_password_strength("Password1", check_breaches=False)
        self.assertGreaterEqual(result['score'], 3)
        self.assertLessEqual(result['score'], 4)
    
    def test_strong_password(self):
        """Test strong password detection"""
        result = check_password_strength("MyP@ssw0rd!2024", check_breaches=False)
        self.assertEqual(result['score'], 6)
        self.assertIn("Strong", result['strength'])
    
    def test_common_password_override(self):
        """Test that common passwords are flagged regardless of complexity"""
        result = check_password_strength(
            "password", 
            common_passwords=self.common_passwords,
            check_breaches=False
        )
        self.assertEqual(result['score'], 0)
        self.assertTrue(result['is_common'])
    
    # ==================== Character Criteria Tests ====================
    
    def test_length_check(self):
        """Test minimum length requirement"""
        short_pwd = check_password_strength("Abc1!", check_breaches=False)
        long_pwd = check_password_strength("Abc1!xyz", check_breaches=False)
        
        # Short password should have lower score
        self.assertLess(short_pwd['score'], long_pwd['score'])
    
    def test_uppercase_requirement(self):
        """Test uppercase letter requirement"""
        no_upper = check_password_strength("password123!", check_breaches=False)
        with_upper = check_password_strength("Password123!", check_breaches=False)
        
        self.assertGreater(with_upper['score'], no_upper['score'])
    
    def test_digit_requirement(self):
        """Test digit requirement"""
        no_digit = check_password_strength("Password!", check_breaches=False)
        with_digit = check_password_strength("Password1!", check_breaches=False)
        
        self.assertGreater(with_digit['score'], no_digit['score'])
    
    def test_special_char_requirement(self):
        """Test special character requirement"""
        no_special = check_password_strength("Password123", check_breaches=False)
        with_special = check_password_strength("Password123!", check_breaches=False)
        
        self.assertGreater(with_special['score'], no_special['score'])
    
    # ==================== Feedback Tests ====================
    
    def test_feedback_for_weak_password(self):
        """Test that weak passwords get helpful feedback"""
        result = check_password_strength("pass", check_breaches=False)
        self.assertGreater(len(result['feedback']), 0)
        self.assertTrue(
            any('8 characters' in fb for fb in result['feedback'])
        )
    
    def test_feedback_for_strong_password(self):
        """Test that strong passwords get minimal feedback"""
        result = check_password_strength("MyStr0ng!P@ssw0rd", check_breaches=False)
        # Should have minimal feedback (maybe just suggesting 12+ chars)
        self.assertLessEqual(len(result['feedback']), 1)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_empty_password(self):
        """Test handling of empty password"""
        result = check_password_strength("", check_breaches=False)
        self.assertEqual(result['score'], 0)
    
    def test_very_long_password(self):
        """Test handling of very long passwords"""
        long_pwd = "A" * 1000 + "1" * 1000 + "!" * 100
        result = check_password_strength(long_pwd, check_breaches=False)
        self.assertEqual(result['score'], 6)
        self.assertGreater(result['entropy'], 1000)
    
    def test_unicode_characters(self):
        """Test handling of unicode characters"""
        unicode_pwd = "P@ssw0rd🔐2024"
        result = check_password_strength(unicode_pwd, check_breaches=False)
        # Should still work
        self.assertGreater(result['score'], 0)
    
    def test_whitespace_password(self):
        """Test password with whitespace"""
        pwd_with_space = "My Pass word 123!"
        result = check_password_strength(pwd_with_space, check_breaches=False)
        # Should count space as special character
        self.assertGreater(result['score'], 0)


def run_tests():
    """Run all tests and display results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
