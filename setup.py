from setuptools import setup, find_packages

# Read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="python-crypto",
    version="0.1.0",
    author="Irfan Kodakkadan",
    author_email="irfan00roshan@gmail.com",
    description="A CLI tool to sign and verify messages using ECDSA.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/irfan43/PythonCrypto",  # Replace with your project's URL
    packages=find_packages(),  # Automatically find the 'python_crypto' package
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.6",
    install_requires=[
        "ecdsa",
    ],
    entry_points={
        "console_scripts": [
            "pythoncrypto = python_crypto.main:main",
        ],
    },
)
