---

## 🔧 Technologies Used

- **Python 3.8+** - Core language
- **Flask** - Web framework
- **Requests** - HTTP library for API calls
- **Hashlib** - SHA-1 hashing for breach detection
- **HTML/CSS/JavaScript** - Web interface

---

## 🔒 Security & Privacy

### k-Anonymity Model
This tool uses the k-anonymity model when checking passwords against breach databases:

1. Password is hashed locally using SHA-1
2. Only the **first 5 characters** of the hash are sent to the API
3. API returns all hashes starting with those 5 characters
4. Full hash comparison happens **locally on your machine**

**Your password is NEVER transmitted over the network.**

---

## 📊 Password Strength Criteria

| Criterion | Requirement | Points |
|-----------|-------------|--------|
| Minimum Length | ≥ 8 characters | +1 |
| Extended Length | ≥ 12 characters | +1 |
| Uppercase Letters | At least one (A-Z) | +1 |
| Lowercase Letters | At least one (a-z) | +1 |
| Digits | At least one (0-9) | +1 |
| Special Characters | At least one (!@#$...) | +1 |

**Scoring:**
- 0-2 points: 🔴 Weak
- 3-4 points: 🟡 Medium
- 5-6 points: 🟢 Strong

**Overrides:**
- Common password: 🔴 Very Weak (0 points)
- Found in breaches: 🔴 Compromised

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- **HaveIBeenPwned** - Troy Hunt's breach detection API
- **SecLists** - Common passwords database by Daniel Miessler
- **NIST** - Password guidelines and recommendations

---

## 📧 Contact

Project Link: [https://github.com/MarkMedhat4/password-security-checker](https://github.com/MarkMedhat4/password-security-checker)

---

## 🔮 Future Improvements

- [ ] Password generator
- [ ] Multi-language support (Arabic/English)
- [ ] Browser extension
- [ ] Mobile app version
- [ ] Password strength history tracking
- [ ] Export reports to PDF

---

**Made with ❤️ for Cybersecurity**
