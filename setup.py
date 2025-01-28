import os
from setuptools import setup, find_packages

setup(
    name="gatecode",
    version="0.0.1.dev2",
    author="Code Gates",
    author_email="admin@gatecode.org",
    description="Gate Your Code's Security",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://www.gatecode.org",  # Replace with your project's URL
    packages=find_packages(include=["gatecode", "gatecode.*"]),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "pycryptodomex>=3.9.9",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
