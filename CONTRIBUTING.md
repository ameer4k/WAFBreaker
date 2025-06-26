# Contributing to WAFBreaker

🛡️ **Thank you for your interest in contributing to WAFBreaker!**

We welcome contributions from security researchers, developers, and anyone interested in improving web application security testing tools.

## 🎯 Ways to Contribute

### 🐛 Bug Reports
- **Search existing issues** before creating a new one
- **Use the bug report template** when available
- **Include detailed information**: OS, Python version, WAF type, payload used
- **Provide steps to reproduce** the issue
- **Add screenshots** if applicable

### ✨ Feature Requests
- **Check existing feature requests** to avoid duplicates
- **Clearly describe the feature** and its use case
- **Explain why it would be valuable** to other users
- **Consider security implications** of new features

### 🔧 Code Contributions
- **New payload modules** for different attack vectors
- **WAF bypass techniques** and evasion methods
- **Performance improvements** and optimizations
- **Bug fixes** and security patches
- **Documentation improvements**

### 📚 Documentation
- **README improvements**
- **Code comments** and docstrings
- **Usage examples** and tutorials
- **Security best practices** documentation

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Basic understanding of web security concepts
- Familiarity with WAF bypass techniques (for payload contributions)

### Development Setup

1. **Fork the repository**
   ```bash
   # Click the "Fork" button on GitHub
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/WAFBreaker.git
   cd WAFBreaker
   ```

3. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # If available
   ```

5. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/issue-description
   ```

## 📝 Development Guidelines

### Code Style
- **Follow PEP 8** Python style guidelines
- **Use meaningful variable names** and function names
- **Add docstrings** to all functions and classes
- **Keep functions focused** and single-purpose
- **Comment complex logic** and WAF bypass techniques

### Security Considerations
- **Never include real vulnerabilities** in example code
- **Sanitize any sensitive information** from commits
- **Test payloads responsibly** on authorized systems only
- **Document security implications** of new features

### Payload Development
When contributing new payloads:

```python
# Example payload structure
class NewPayloadModule:
    def __init__(self):
        self.name = "Descriptive Name"
        self.category = "xss|sqli|cmdi|lfi|etc"
        self.description = "Brief description of the technique"
    
    def generate_payload(self, target_param, options=None):
        """
        Generate payload with proper documentation
        
        Args:
            target_param (str): Parameter to inject into
            options (dict): Additional options for customization
            
        Returns:
            list: List of generated payloads
        """
        # Implementation here
        pass
```

### Testing
- **Test on multiple WAF types** when possible
- **Include unit tests** for new functions
- **Verify payload effectiveness** in controlled environments
- **Test edge cases** and error conditions

## 🔍 Pull Request Process

### Before Submitting
1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Run existing tests** to ensure nothing breaks
4. **Update CHANGELOG.md** if applicable
5. **Verify all WAF bypass techniques** work as intended

### Pull Request Guidelines
1. **Use a clear title** describing the change
2. **Reference related issues** using `#issue-number`
3. **Describe what you changed** and why
4. **Include testing details** and results
5. **Add screenshots** for UI changes

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested on [WAF_TYPE]
- [ ] Unit tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No sensitive information included
```

## 🛡️ Security and Ethics

### Responsible Disclosure
- **Report security vulnerabilities** privately to maintainers
- **Do not create public issues** for security vulnerabilities
- **Allow time for fixes** before public disclosure

### Ethical Guidelines
- **Use only for authorized testing** and educational purposes
- **Respect system boundaries** and permissions
- **Follow responsible disclosure** practices
- **Consider impact** on real-world security

### Prohibited Contributions
- **Malicious payloads** designed to cause harm
- **Exploits for 0-day vulnerabilities** without coordination
- **Illegal techniques** or methods
- **Unethical hacking tools** or methodologies

## 📞 Getting Help

### Communication Channels
- **GitHub Issues** - For bugs and feature requests
- **GitHub Discussions** - For questions and community interaction
- **Email** - For security-related concerns (if provided)

### Questions?
- **Check existing documentation** first
- **Search closed issues** for similar problems
- **Ask in GitHub Discussions** for general questions
- **Create an issue** for specific bugs or feature requests

## 🏆 Recognition

Contributors will be recognized in:
- **README.md** contributor section
- **CHANGELOG.md** for significant contributions
- **Release notes** for major features

## 📋 Code of Conduct

- **Be respectful** and professional
- **Focus on constructive feedback**
- **Help newcomers** learn and contribute
- **Follow ethical hacking principles**
- **Respect intellectual property** and licensing

---

**By contributing to WAFBreaker, you agree to license your contributions under the same MIT License that covers the project.**

Thank you for helping make WAFBreaker better and more secure! 🚀