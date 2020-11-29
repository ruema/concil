import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="concil",
    version="0.3.0",
    author="ruema",
    description="container manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ruema/concil",
    packages=['concil'],
    entry_points={
        'console_scripts': [
            'concil_cli=concil.cli:main',
        ],
    },
    install_requires=['cryptography', 'jwcrypto', 'requests'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
)
