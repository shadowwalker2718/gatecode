# GateCode - Secure Your Python Code 🔒

Python's simplicity and flexibility come with a trade-off: source code is easily exposed when published or deployed. GateCode provides a secure solution to this long-standing problem by enabling you to encrypt your Python scripts, allowing deployment without revealing your IP(intellectual property) or secret in the source code.

## Key Features 🔍

- **Secure Code Encryption**: Protect your intellectual property by encrypting your Python scripts.
- **Easy Integration**: Minimal effort required to integrate the encrypted package into your projects.
- **Cross-Platform Deployment**: Deploy your encrypted code to any environment without exposing its contents.

---

<iframe width="560" height="315" src="https://www.youtube.com/embed/UMswFxcbPRY?si=tKNik98aGy_xV-vX" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## How It Works ⚙️

### 0. Install `gatecode` 🚀

Just run the command to install `gatecode`, which would be used later:

```
pip install gatecode
```

### 1. Prepare Your Python Script 🔧

Suppose you have a Python file named `my_awesome_code.py` containing sensitive logic:

```python
# secret algorithm with secret numbers
def func(a, b):
    return a * 31 + b * 71
```

### 2. Encrypt Your Script 🛡️

Go to [GateCode](https://www.gatecode.org) and upload your Python script. The system will generate an encrypted package for you, which can be safely deployed.

Once encrypted, you will receive a file, for example: `my_valuable_code`.

### 3. Integrate Encrypted Package 🔐

Use the following script to load and use your encrypted code:

```python
import os
from gatecode import add_dp_package

# Pass the absolute path of the downloaded file to add_dp_package (note: do not remove the underscore _)
here = os.path.dirname(os.path.abspath(__file__))
_ = add_dp_package(os.path.join(here, 'my_valuable_code'))

# Import and use `my_awesome_code` (adjust it according to your Python file's name) 
import my_awesome_code

# Example usage
print(my_awesome_code.func(1, 2))
```

---

## Example Use Case 📊

Imagine you’ve developed a proprietary algorithm that you need to deploy to your clients. Using GateCode:
1. Encrypt the Python script containing your algorithm.
2. Provide the encrypted package to your client.
3. Your client integrates the package without accessing the original source code.

This ensures that your intellectual property is secure while maintaining usability.

---

## Why GateCode? 🌎

- **Protect Sensitive Logic**: Prevent unauthorized access to your code.
- **Simple Deployment**: No complicated setup or runtime requirements.
- **Peace of Mind**: Focus on your work without worrying about code theft.

---

### Get Started Now 🏃‍♂️

1. Visit [GateCode](https://www.gatecode.org).
2. Upload your Python script.
3. Download your encrypted package and deploy it securely.

Secure your Python code with GateCode today!

