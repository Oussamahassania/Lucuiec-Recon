from setuptools import setup, find_packages

setup(
    name="lucuiec-recon",
    version="3.0.0",
    author="Oussamahassania",
    description="Ultimate Web Hacking Recon Framework — Bug Bounty / CTF",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Oussamahassania/Lucuiec-Recon",
    packages=find_packages(),
    include_package_data=True,         # Include wordlists
    package_data={
        "lucuiec_recon": [
            "wordlists/*.txt",
        ]
    },
    install_requires=[
        "httpx>=0.25.0",
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "colorama>=0.4.6",
        "python-nmap>=0.7.1",
    ],
    entry_points={
        "console_scripts": [
            # This is the magic line:
            # "lucuiec-recon" = the command name anyone types
            # "lucuiec_recon.main:main" = calls main() in lucuiec_recon/main.py
            "lucuiec-recon=lucuiec_recon.main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
)