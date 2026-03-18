from setuptools import setup, find_packages

setup(
    name="corsbuster",
    version="1.1.0",
    description="CORS Misconfiguration Scanner with Exploitability Verification",
    author="CyberWarrior9",
    url="https://github.com/CyberWarrior9/corsbuster",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.0",
        "rich>=13.0.0",
        "tldextract>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "corsbuster=corsbuster.__main__:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
