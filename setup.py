from setuptools import find_packages, setup

setup(
    name="lanimals",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests", "flask", "scapy"],
    entry_points={
        "console_scripts": [
            "lanimals=LANimals:main",
        ],
    },
)
